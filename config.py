from enum import Enum

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from dotenv import load_dotenv

load_dotenv()

# Used when env sets RABBITMQ_URL to empty string (e.g. compose `${VAR}` unset overrides default).
_DEFAULT_RABBITMQ_URL = "amqp://guest:guest@localhost:5672/"

class Permissions(str, Enum):
    USERS_READ_ALL = "auth.user.all:read"
    USERS_WRITE_ALL = "auth.user.all:write"

    ROLES_READ_ALL = "auth.role.all:read"
    ROLES_WRITE_ALL = "auth.role.all:write"
    ROLES_DELETE_ALL = "auth.role.all:delete"

    PERMISSIONS_READ_ALL = "auth.permission.all:read"
    PERMISSIONS_WRITE_ALL = "auth.permission.all:write"
    PERMISSIONS_DELETE_ALL = "auth.permission.all:delete"

    USERS_READ_OWN = "auth.user.own:read"
    USERS_WRITE_OWN = "auth.user.own:write"


class Environment(str, Enum):
    DEVELOPMENT = "development"
    PRODUCTION = "production"

class Settings(BaseSettings):
    # Database

    DB_HOST: str = "localhost"
    DB_PORT: str = "5432"
    DB_NAME: str = "test_db"
    DB_USER: str = "postgres"
    DB_PASS: str = "testpass"


    # Redis
    REDIS_URL: str = "redis://localhost:6379"

    # AWS
    AWS_REGION: str = "eu-north-1"
    AWS_ACCESS_KEY_ID: str = ""
    AWS_SECRET_ACCESS_KEY: str = ""
    AWS_KMS_KEY_ARN: str = 'arn:aws:kms:eu-north-1:669409472579:key/a0e62c95-68a4-4cb2-814f-7b02b654a878'

    # Security
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Application
    APP_NAME: str = "auth-service"
    AUDIENCE: str = "web-api"
    DEBUG: bool = True
    ROOT_PATH: str = ''
    ENVIRONMENT: Environment = Environment.DEVELOPMENT

    @property
    def enable_docs(self) -> bool:
        return self.ENVIRONMENT in [Environment.DEVELOPMENT]


    # RabbitMQ — host and port required. In password, encode @ as %40, : as %3A, # as %23, / as %2F.
    RABBITMQ_URL: str = _DEFAULT_RABBITMQ_URL
    RABBITMQ_EXCHANGE_NAME: str = 'events'

    # rpc
    GRPC_SERVER_PORT: int = 50054

    RPC_PAYMENT_URL: str = "localhost:50053"

    @field_validator("RABBITMQ_URL", mode="before")
    @classmethod
    def rabbitmq_url_drop_empty_env(cls, v: object) -> object:
        """Docker Compose often sets RABBITMQ_URL=${RABBITMQ_URL}; if unset, that becomes '' and would override the default with an unparseable URL."""
        if isinstance(v, str) and not v.strip():
            return _DEFAULT_RABBITMQ_URL
        return v

    model_config = SettingsConfigDict(env_file=".env")



settings = Settings()


def aws_boto_session_kwargs() -> dict:
    """Kwargs for aioboto3.Session. If access keys are unset, boto uses the default chain (e.g. EC2 instance role, ~/.aws/credentials)."""
    kw: dict = {"region_name": settings.AWS_REGION}
    if settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY:
        kw["aws_access_key_id"] = settings.AWS_ACCESS_KEY_ID
        kw["aws_secret_access_key"] = settings.AWS_SECRET_ACCESS_KEY
    return kw