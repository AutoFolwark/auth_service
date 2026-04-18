from contextlib import asynccontextmanager
from typing import Optional, Callable
import redis
from fastapi import FastAPI, APIRouter
from fastapi_limiter import FastAPILimiter
from fastapi_pagination import add_pagination
from fastapi_problem.handler import add_exception_handler, new_exception_handler

from config import settings
from core.logger import logger
from routers.v1.private.permission import permissions_router
from routers.v1.private.role import roles_router
from routers.v1.private.user import user_control_router
from routers.v1.public.auth import auth_v1_router
from routers.v1.public.password_reset import password_reset_router
from routers.v1.public.verification_code import verification_code_router
from routers.v1.public.verify import verify_request_router


async def setup_fastapi_limiter(redis_client: Optional[redis.Redis] = None, prefix: str = "rl:"):
    if redis_client is None:
        redis_client = redis.asyncio.from_url(settings.REDIS_URL, encoding="utf-8", decode_responses=True)
    await FastAPILimiter.init(redis_client, prefix=prefix)


def setup_routers(app: FastAPI):
    v1_router = APIRouter(prefix="/v1")

    v1_router.include_router(auth_v1_router, tags=["auth"])
    v1_router.include_router(verify_request_router, tags=["internal"])
    v1_router.include_router(verification_code_router, prefix="/verification-code", tags=["verification-code"])
    v1_router.include_router(password_reset_router, prefix="/password-reset", tags=["password-reset"])

    private_router = APIRouter(prefix="/private")
    private_router.include_router(user_control_router, tags=["user"])
    private_router.include_router(roles_router, tags=["roles"])
    private_router.include_router(permissions_router, tags=["permissions"])

    v1_router.include_router(private_router)
    app.include_router(v1_router)

    @app.get("/health")
    async def health_check():
        return {"status": "healthy", "service": settings.APP_NAME}


def setup_middleware_and_handlers(app: FastAPI):
    eh = new_exception_handler()
    add_exception_handler(app, eh)
    add_pagination(app)


def create_app(
        setup_limiter: bool = True,
        custom_redis_client: Optional[redis.Redis] = None,
        lifespan_override: Optional[Callable] = None
) -> FastAPI:
    @asynccontextmanager
    async def default_lifespan(_: FastAPI):

        if setup_limiter:
            await setup_fastapi_limiter(custom_redis_client)

        logger.info(f"{settings.APP_NAME} started!")
        yield

        if setup_limiter:
            await FastAPILimiter.close()

    docs_url = "/docs" if settings.enable_docs else None
    redoc_url = "/redoc" if settings.enable_docs else None
    openapi_url = "/openapi.json" if settings.enable_docs else None

    app = FastAPI(
        title="Auth Service",
        description="JWT Authentication Service with AWS KMS",
        version="0.0.1",
        root_path=settings.ROOT_PATH,
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
        lifespan=lifespan_override or default_lifespan
    )

    setup_middleware_and_handlers(app)
    setup_routers(app)

    return app