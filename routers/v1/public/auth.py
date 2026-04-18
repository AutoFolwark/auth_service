from fastapi import Depends, APIRouter, Body, Request, Security, Response
from rfc9457 import UnauthorisedProblem, ServerProblem, Problem
from sqlalchemy.exc import MultipleResultsFound, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, UTC, timedelta
import uuid

from starlette import status

from auth_utils.service import AuthService, TokenType
from base_checks import check_user
from config import settings, Environment
from core.logger import logger

from custom_exceptions import RegisteredWithPresentCredentialsProblem
from database.crud.many_to_many.user_role import UserRoleService
from database.crud.refresh_token import RefreshTokenService
from database.crud.role import RoleService

from database.crud.user import UserService
from database.crud.user_session import UserSessionService
from database.db.session import get_async_db
from database.models import User
from database.schemas.many_to_many.user_role import UserRoleCreate
from database.schemas.refresh_token import RefreshTokenCreate
from database.schemas.user import (
    UserCreate, UserRead
)

from database.schemas.user_session import UserSessionCreate, UserSessionUpdate
from deps import get_auth_service, get_rate_limiter
from schemas.request_schemas.logout import LogoutRequest
from schemas.request_schemas.refresh import RefreshTokenIn
from schemas.request_schemas.registration import UserIn, EmailPassIn
from schemas.request_schemas.token import TokenResponse
from dependencies.security import get_current_user
from utils.decode_user_agent import device_name_from_user_agent, client_ip_from_request

auth_v1_router = APIRouter()


@auth_v1_router.post(
    "/register",
    response_model=UserRead,
    status_code=201,
    summary="Register a new user",
    description="Create a new user account with email, username, and password.",
    dependencies=[get_rate_limiter(times=15, seconds=120)]
)
async def register(
        user_data: UserIn = Body(..., description="User registration payload"),
        response: Response = None,
        db: AsyncSession = Depends(get_async_db),
        auth_service: AuthService = Depends(get_auth_service),
) -> User:
    logger.info('Registration attempt', extra={"email": user_data.email, "phone_number": user_data.phone_number})
    try:
        user_service = UserService(db)
        role_service = RoleService(db)
        user_role_service = UserRoleService(db)

        email_value = str(user_data.email)
        phone_value = user_data.phone_number


        try:
            by_email = await user_service.get_by_email(email_value)
            by_phone = await user_service.get_by_phone_number(phone_value)
            logger.debug('Checking for existing credentials', extra={"email": by_email, "phone_number": by_phone})

        except MultipleResultsFound:
            logger.error('Registration failed - Multiple results found', extra={"email": email_value, "phone_number": phone_value})
            raise ServerProblem(detail="Multiple results found for email or phone number")

        if by_email and getattr(by_email, "email_verified", False):
            logger.warning('Registration failed - email verified', extra={"email": email_value, "user_id": by_email.id})
            raise RegisteredWithPresentCredentialsProblem(detail="Email already registered and verified")

        if by_phone and getattr(by_phone, "phone_verified", False):
            logger.warning('Registration failed - phone verified', extra={"phone_number": phone_value, "user_id": by_phone.id})
            raise RegisteredWithPresentCredentialsProblem(detail="Phone number already registered and verified")

        if by_email:
            if by_phone and by_phone.id != by_email.id:
                by_phone.phone_number = ''
                await db.flush()
            by_email.phone_number = phone_value
            by_email.first_name = user_data.first_name
            by_email.last_name = user_data.last_name
            by_email.password_hash = auth_service.hash_password(user_data.password)
            try:
                await db.commit()
                await db.refresh(by_email)
            except IntegrityError as ie:
                await db.rollback()
                logger.error('Integrity error on update (email branch)', extra={"email": email_value, "phone_number": phone_value, "error": str(ie)})
                raise RegisteredWithPresentCredentialsProblem(detail="Email or phone number already registered")
            logger.info('Updated unverified user by email', extra={"user_id": by_email.id, "uuid": by_email.uuid_key})
            response.status_code = status.HTTP_201_CREATED
            return by_email

        if by_phone:
            by_phone.email = email_value
            by_phone.username = email_value.split('@')[0]
            by_phone.first_name = user_data.first_name
            by_phone.last_name = user_data.last_name
            by_phone.password_hash = auth_service.hash_password(user_data.password)
            try:
                await db.commit()
                await db.refresh(by_phone)
            except IntegrityError as ie:
                await db.rollback()
                logger.error('Integrity error on update (phone branch)', extra={"email": email_value, "phone_number": phone_value, "error": str(ie)})
                raise RegisteredWithPresentCredentialsProblem(detail="Email or phone number already registered")
            logger.info('Updated unverified user by phone', extra={"user_id": by_phone.id, "uuid": by_phone.uuid_key})
            response.status_code = status.HTTP_201_CREATED
            return by_phone

        password_hash = auth_service.hash_password(user_data.password)
        default_role = await role_service.get_default_role()
        user_uuid = str(uuid.uuid4())

        new_user_data = UserCreate(
            uuid_key=user_uuid,
            password_hash=password_hash,
            email=user_data.email,
            phone_number=phone_value,
            username=email_value.split('@')[0],
            first_name=user_data.first_name,
            last_name=user_data.last_name,
        )

        try:
            user = await user_service.create(new_user_data, flush=True)
            await user_role_service.create(UserRoleCreate(user_id=user.id, role_id=default_role.id))
            await db.commit()
            await db.refresh(user)
        except IntegrityError as ie:
            await db.rollback()
            logger.error('Integrity error on create', extra={"email": email_value, "phone_number": phone_value, "error": str(ie)})
            raise RegisteredWithPresentCredentialsProblem(detail="Email or phone number already registered")

        logger.info('Registration successful', extra={"user_id": user.id, "uuid": user_uuid})
        response.status_code = status.HTTP_201_CREATED
        return user

    except Problem:
        raise
    except Exception as e:
        logger.error('Registration failed - unexpected error', extra={"email": user_data.email, "phone_number": user_data.phone_number, "error": str(e), "error_type": type(e).__name__})
        raise


@auth_v1_router.post("/login", response_model=TokenResponse,
                     description="Login and receive tokens",
                     summary="Login",
                     dependencies=[get_rate_limiter(times=10, seconds=60)])
async def login(request: Request,
                response: Response,
                credentials: EmailPassIn = Body(...),
                db: AsyncSession = Depends(get_async_db),
                auth_service: AuthService = Depends(get_auth_service)):
    user_agent = request.headers.get("user-agent", "")
    device_name = request.headers.get("x-device-name") or device_name_from_user_agent(user_agent)
    ip_address = client_ip_from_request(request)

    logger.info(f'Login attempt', extra={
        "email": credentials.email,
        "ip_address": ip_address,
        "device_name": device_name,
        "user_agent": user_agent[:100]
    })

    try:
        user_service = UserService(db)
        user = await user_service.get_by_email(str(credentials.email))

        if not user:
            logger.warning(f'Login failed - user not found', extra={
                "email": credentials.email,
                "ip_address": ip_address
            })
            raise UnauthorisedProblem(detail="Invalid email or password")

        check_user(user)

        if not auth_service.verify_password(credentials.password, str(user.password_hash)):
            logger.warning(f'Login failed - invalid password', extra={
                "email": credentials.email,
                "user_id": user.id,
                "ip_address": ip_address
            })
            raise UnauthorisedProblem(detail="Invalid email or password")

        logger.debug(f'Extracting roles and permissions', extra={
            "user_id": user.id,
            "email": credentials.email
        })

        access_token_payload = await auth_service.get_payload_for_token(
            user=user,
            token_type=TokenType.ACCESS
        )
        refresh_token_payload = await auth_service.get_payload_for_token(
            user=user,
            token_type=TokenType.REFRESH
        )

        logger.debug(f'Creating refresh token record', extra={
            "user_id": user.id,
            "jti": refresh_token_payload["jti"],
            "token_family": refresh_token_payload["token_family"]
        })

        refresh_token_service = RefreshTokenService(db)
        refresh_token_data = RefreshTokenCreate(
            jti=refresh_token_payload["jti"],
            user_id=user.id,
            token_family=refresh_token_payload["token_family"],
            issued_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(seconds=auth_service.refresh_token_ttl),
            device_name=device_name,
            user_agent=user_agent,
            ip_address=ip_address,
            is_active=True,
        )

        refresh_token_created = await refresh_token_service.create(refresh_token_data)

        logger.debug(f'Creating user session', extra={
            "user_id": user.id,
            "refresh_token_id": refresh_token_created.id
        })

        user_session_service = UserSessionService(db)
        session_key = str(uuid.uuid4())
        user_session_data = UserSessionCreate(
            user_id=user.id,
            session_key=session_key,
            refresh_token_id=refresh_token_created.id
        )
        session = await user_session_service.create(user_session_data)

        access_token = await auth_service.generate_token(access_token_payload)
        refresh_token = await auth_service.generate_token(refresh_token_payload)

        response.set_cookie(
            key="access_token",
            value=access_token,
            max_age=auth_service.access_token_ttl,
            httponly=True,
            secure=settings.ENVIRONMENT == Environment.PRODUCTION,
            samesite="lax"
        )

        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            max_age=auth_service.refresh_token_ttl,
            httponly=True,
            secure=settings.ENVIRONMENT == Environment.PRODUCTION,
            samesite="lax"
        )

        logger.info(f'Login successful - tokens set in cookies', extra={
            "email": credentials.email,
            "user_id": user.id,
            "user_uuid": user.uuid_key,
            "session_id": session.id if hasattr(session, 'id') else None,
            "session_key": session_key,
            "ip_address": ip_address,
            "device_name": device_name,
            "access_jti": access_token_payload["jti"],
            "refresh_jti": refresh_token_payload["jti"]
        })

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
        }

    except Problem:
        raise
    except Exception as e:
        logger.error(f'Login failed - unexpected error', extra={
            "email": credentials.email,
            "ip_address": ip_address,
            "error": str(e),
            "error_type": type(e).__name__
        })
        raise


@auth_v1_router.post("/refresh", response_model=TokenResponse, description="Rotate refresh and issue new tokens",
                     summary="Refresh")
async def refresh_token_pair(
        data: RefreshTokenIn = Body(...),
        db: AsyncSession = Depends(get_async_db),
        auth_service: AuthService = Depends(get_auth_service)
):
    logger.info('Token refresh attempt')

    try:
        payload = await auth_service.verify_token(data.refresh_token)
        presented_jti = payload.get("jti")

        logger.debug(f'Verifying refresh token', extra={
            "jti": presented_jti,
            "token_type": payload.get("type"),
            "user_uuid": payload.get("sub")
        })

        if not presented_jti or await auth_service.is_token_blacklisted(TokenType.REFRESH, presented_jti):
            logger.warning(f'Refresh failed - token blacklisted or invalid', extra={
                "jti": presented_jti
            })
            raise UnauthorisedProblem(detail="Refresh token expired or revoked, please login again")

        if not payload or payload.get("type") != "refresh":
            logger.warning(f'Refresh failed - invalid token type', extra={
                "jti": presented_jti,
                "token_type": payload.get("type")
            })
            raise UnauthorisedProblem(detail="Invalid refresh token")

        user_service = UserService(db)
        user = await user_service.get_user_by_uuid(str(payload.get("sub")))

        if not user:
            logger.warning(f'Refresh failed - user not found', extra={
                "user_uuid": payload.get("sub"),
                "jti": presented_jti
            })
            raise UnauthorisedProblem(detail="User not found or inactive")

        if not user.is_active:
            logger.warning(f'Refresh failed - user inactive', extra={
                "user_id": user.id,
                "user_uuid": user.uuid_key,
                "jti": presented_jti
            })
            raise UnauthorisedProblem(detail="User not found or inactive")

        refresh_token_service = RefreshTokenService(db)
        user_session_service = UserSessionService(db)

        refresh_token = await refresh_token_service.get_by_jti(presented_jti)
        session = await user_session_service.get_session_by_refresh_token_id(refresh_token.id)

        logger.debug(f'Retrieved session and token info', extra={
            "user_id": user.id,
            "session_id": session.id if session else None,
            "refresh_token_id": refresh_token.id
        })


        family_id = str(payload.get("token_family"))

        logger.debug(f'Checking token family for reuse', extra={
            "token_family": family_id,
            "presented_jti": presented_jti
        })

        last = await refresh_token_service.get_last_token_in_family(family_id, only_active=True,
                                                                    require_not_expired=True)

        if not last or last.jti != presented_jti:
            logger.critical(f'Token reuse detected - revoking entire family', extra={
                "user_id": user.id,
                "user_email": user.email,
                "token_family": family_id,
                "presented_jti": presented_jti,
                "expected_jti": last.jti if last else None
            })
            await refresh_token_service.revoke_family(family_id)
            await auth_service.blacklist_token(TokenType.REFRESH, presented_jti)
            raise UnauthorisedProblem(detail="Refresh token reuse detected")

        now = datetime.now(UTC)
        new_refresh_payload = await auth_service.get_payload_for_token(
            user=user,
            token_type=TokenType.REFRESH,
            token_family=family_id
        )
        new_access_payload = await auth_service.get_payload_for_token(
            user=user,
            token_type=TokenType.ACCESS
        )

        logger.debug(f'Rotating refresh token', extra={
            "user_id": user.id,
            "old_jti": presented_jti,
            "new_jti": new_refresh_payload["jti"],
            "token_family": family_id
        })

        new_expires_at = now + timedelta(seconds=auth_service.refresh_token_ttl)
        new_refresh_token = await refresh_token_service.rotate_refresh(
            current_jti=presented_jti,
            new_jti=str(new_refresh_payload["jti"]),
            new_expires_at=new_expires_at
        )

        session_data = UserSessionUpdate(refresh_token_id=new_refresh_token.id, last_activity=now)
        await user_session_service.update(session.id, session_data)

        access_token = await auth_service.generate_token(new_access_payload)
        refresh_token = await auth_service.generate_token(new_refresh_payload)

        await auth_service.blacklist_token(TokenType.REFRESH, presented_jti)

        logger.info(f'Token refresh successful', extra={
            "user_id": user.id,
            "user_email": user.email,
            "session_id": session.id,
            "old_jti": presented_jti,
            "new_access_jti": new_access_payload["jti"],
            "new_refresh_jti": new_refresh_payload["jti"],
            "token_family": family_id
        })

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
        }

    except Problem:
        raise
    except Exception as e:
        logger.error(f'Token refresh failed - unexpected error', extra={
            "error": str(e),
            "error_type": type(e).__name__
        })
        raise


@auth_v1_router.post("/logout")
async def logout(
        token_data: dict = Security(get_current_user),
        refresh_token_data: LogoutRequest = Body(...),
        auth_service: AuthService = Depends(get_auth_service),
        db: AsyncSession = Depends(get_async_db),
):
    access_jti = token_data.get("jti")
    user_uuid = str(token_data.get("sub"))

    logger.info(f'Logout attempt', extra={
        "user_uuid": user_uuid,
        "access_jti": access_jti
    })

    try:
        refresh_payload = await auth_service.verify_token(refresh_token_data.refresh_token)
        refresh_jti = str(refresh_payload.get("jti"))

        logger.debug(f'Verifying logout tokens', extra={
            "user_uuid": user_uuid,
            "access_jti": access_jti,
            "refresh_jti": refresh_jti
        })

        # Blacklist both tokens
        await auth_service.blacklist_token(TokenType.ACCESS, access_jti)
        await auth_service.blacklist_token(TokenType.REFRESH, refresh_jti)

        logger.debug(f'Tokens blacklisted, updating session', extra={
            "access_jti": access_jti,
            "refresh_jti": refresh_jti
        })

        user_session_service = UserSessionService(db)
        user_service = UserService(db)
        refresh_token_service = RefreshTokenService(db)

        refresh_token_obj = await refresh_token_service.get_by_jti(refresh_jti)
        user = await user_service.get_user_by_uuid(user_uuid)

        if not refresh_token_obj:
            logger.warning(f'Logout failed - refresh token not found', extra={
                "user_uuid": user_uuid,
                "refresh_jti": refresh_jti
            })
            raise UnauthorisedProblem(detail="Invalid refresh token")

        session = await user_session_service.get_session_by_refresh_token_id(refresh_token_obj.id)

        if not session or not user:
            logger.warning(f'Logout failed - session or user not found', extra={
                "user_uuid": user_uuid,
                "user_found": user is not None,
                "session_found": session is not None,
                "refresh_token_id": refresh_token_obj.id if refresh_token_obj else None
            })
            raise UnauthorisedProblem(detail="Invalid refresh token")

        now = datetime.now(UTC)

        logger.debug(f'Terminating session', extra={
            "user_id": user.id,
            "session_id": session.id,
            "session_key": session.session_key if hasattr(session, 'session_key') else None
        })

        user_session_data = UserSessionUpdate(is_active=False, terminated_at=now)
        await user_session_service.update(session.id, user_session_data)

        logger.info(f'Logout successful', extra={
            "user_id": user.id,
            "user_email": user.email,
            "user_uuid": user_uuid,
            "session_id": session.id,
            "access_jti": access_jti,
            "refresh_jti": refresh_jti,
            "terminated_at": now.isoformat()
        })

        return {"message": "Successfully logged out"}

    except Problem:
        raise
    except Exception as e:
        logger.error(f'Logout failed - unexpected error', extra={
            "user_uuid": user_uuid,
            "access_jti": access_jti,
            "error": str(e),
            "error_type": type(e).__name__
        })
        raise ServerProblem(detail="Unexpected error")