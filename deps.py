from typing import Any, AsyncGenerator, Callable

from fastapi_limiter.depends import RateLimiter
from sqlalchemy.ext.asyncio import AsyncSession
from auth_utils.service import AuthService
import aioboto3
import redis
from aioboto3 import Session
from fastapi import Depends
from redis.asyncio import Redis

from core.logger import logger
from config import aws_boto_session_kwargs, settings
from custom_exceptions import MessagingUnavailableProblem, raise_rate_limiter_error
from database.crud.singin_key import SigningKeyService
from database.db.session import AsyncSessionLocal, get_async_db
from rabbit_service.service import RabbitMQPublisher
from rate_limit_ids import user_identifier

async def get_redis_client()-> AsyncGenerator[Redis, Any]:
    redis_client = await redis.asyncio.from_url(
        settings.REDIS_URL,
        decode_responses=True
    )
    yield redis_client

async def get_kms_session()-> AsyncGenerator[Session, Any]:
    kms_session = aioboto3.Session(**aws_boto_session_kwargs())
    yield kms_session

async def get_auth_service(redis_client: Redis = Depends(get_redis_client), kms_session: Session = Depends(get_kms_session),
                           db: AsyncSession = Depends(get_async_db))-> AsyncGenerator[AuthService, Any]:
    sign_key_service = SigningKeyService(db)
    active_signing_key = await sign_key_service.get_newer_active_key()
    yield AuthService(kms_session, redis_client, str(active_signing_key.key_arn))

def get_rate_limiter(times: int, seconds: int, identifier=user_identifier, error_callback: Callable = raise_rate_limiter_error):
    limiter = RateLimiter(times=times, seconds=seconds, identifier=identifier, callback=error_callback)
    return Depends(limiter)

async def get_rabbit_mq_service() -> AsyncGenerator[RabbitMQPublisher, None]:
    service = RabbitMQPublisher()
    await service.connect()
    try:
        yield service
    finally:
        await service.close()


async def ensure_rabbitmq_reachable() -> None:
    """Fail fast if RabbitMQ is not accepting connections (e.g. registration)."""
    service = RabbitMQPublisher()
    try:
        await service.connect()
    except Exception as exc:
        logger.exception("RabbitMQ connection failed")
        raise MessagingUnavailableProblem(
            detail="Registration is unavailable: messaging service is not reachable.",
        ) from exc
    finally:
        await service.close()


async def get_async_db_for_register(
    _: None = Depends(ensure_rabbitmq_reachable),
) -> AsyncGenerator[AsyncSession, None]:
    """DB session for registration; RabbitMQ must connect before the session opens."""
    async with AsyncSessionLocal() as session:
        yield session
