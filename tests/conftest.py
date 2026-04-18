from typing import AsyncGenerator, Any

import pytest
import pytest_asyncio
from asgi_lifespan import LifespanManager
from fastapi_limiter import FastAPILimiter
from fastapi_pagination import add_pagination
from httpx import AsyncClient, ASGITransport
from redis import Redis
from sqlalchemy import event, StaticPool, create_engine
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from database.db.session import get_async_db
from database.models import Base
from deps import get_redis_client, get_auth_service, get_rabbit_mq_service
from rabbit_service.service import RabbitMQPublisher
from dependencies.security import get_current_user, require_all_permissions
from scripts.init_db import seed_db
from tests.moks import get_test_redis_client, mock_auth_service, mock_get_current_user, mock_rabbit_mq, \
    mock_require_all_permissions
from utils.app_factory import create_app, setup_fastapi_limiter, \
    setup_middleware_and_handlers


@pytest_asyncio.fixture
async def get_app(
    mock_auth_service,
    mock_get_current_user,
    mock_rabbit_mq,
    session: AsyncSession,
):
    app = create_app()
    await setup_fastapi_limiter(await get_test_redis_client())
    # Use a separate connection for seeding, and close it before yielding the app
    setup_middleware_and_handlers(app)

    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield session

    async def override_get_redis() -> Redis:
        return await get_test_redis_client()

    async def override_get_auth_service() -> AsyncGenerator[Any, None]:
        yield mock_auth_service

    async def override_get_current_user() -> AsyncGenerator[Any, None]:
        yield mock_get_current_user

    async def override_rabbit_mq() -> AsyncGenerator[RabbitMQPublisher, None]:
        yield mock_rabbit_mq

    app.dependency_overrides[get_current_user] = override_get_current_user
    app.dependency_overrides[get_async_db] = override_get_db
    app.dependency_overrides[require_all_permissions] = mock_require_all_permissions
    app.dependency_overrides[get_redis_client] = override_get_redis
    app.dependency_overrides[get_auth_service] = override_get_auth_service
    app.dependency_overrides[get_rabbit_mq_service] = override_rabbit_mq

    return app

@pytest.fixture(autouse=True)
async def initialize_db():
    async with engine_test_async.connect() as conn:
        await conn.run_sync(seed_db)


@pytest_asyncio.fixture
async def client(get_app):
    async with AsyncClient(transport=ASGITransport(get_app), base_url="http://test") as ac:
        yield ac

@pytest_asyncio.fixture
async def db():
    async with engine_test_async.connect() as conn:
        trans = await conn.begin()
        session = AsyncTestSessionLocal(bind=conn)

        await session.begin_nested()

        @event.listens_for(session.sync_session, "after_transaction_end")
        def restart_savepoint(sess, trans_):
            if trans_.nested and not trans_._parent.nested:
                sess.begin_nested()

        yield session

        await session.close()
        await trans.rollback()


TEST_DB_URL = "sqlite+aiosqlite:///:memory:"

engine_test_async = create_async_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
    echo=False,
)



AsyncTestSessionLocal = async_sessionmaker(
    bind=engine_test_async,
    expire_on_commit=False,
    class_=AsyncSession,
)

@pytest_asyncio.fixture
async def session():
    async with engine_test_async.connect() as conn:
        trans = await conn.begin()
        session = AsyncSession(bind=conn, expire_on_commit=False)
        yield session
        await session.close()
        await trans.rollback()

@pytest_asyncio.fixture(scope="session", autouse=True)
async def init_db():
    async with engine_test_async.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine_test_async.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

@pytest.fixture(autouse=True)
def mock_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test_key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test_secret")











