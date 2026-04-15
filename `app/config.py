import os
from dotenv import load_dotenv

load_dotenv()


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


class Settings:
    APP_NAME = "PolicyMesh"
    APP_VERSION = "0.2.0"
    ENV = os.getenv("POLICYMESH_ENV", "development")
    SECRET_KEY = os.getenv("POLICYMESH_SECRET_KEY", "replace-this-with-a-long-random-secret")
    ALGORITHM = os.getenv("POLICYMESH_ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("POLICYMESH_ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
    ALLOWED_HOSTS = _split_csv(os.getenv("POLICYMESH_ALLOWED_HOSTS", "localhost,127.0.0.1"))
    ALLOWED_ORIGINS = _split_csv(
        os.getenv(
            "POLICYMESH_ALLOWED_ORIGINS",
            "http://localhost:3000,http://127.0.0.1:3000",
        )
    )
    RATE_LIMIT_PER_MINUTE = int(os.getenv("POLICYMESH_RATE_LIMIT_PER_MINUTE", "30"))
    AUDIT_LOG_PATH = "logs/policymesh_audit.jsonl"


settings = Settings()
