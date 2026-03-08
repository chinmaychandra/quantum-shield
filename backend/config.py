# config.py — loads all environment variables from .env and exposes settings

# config.py
# Single source of truth for all environment variables.
# Every other file in the backend imports 'settings' from here.
# Never hardcode secrets anywhere else.

from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # Database
    DATABASE_URL: str = "postgresql+asyncpg://user:password@localhost:5432/cbom_db"
    
    # Auth
    SECRET_KEY: str = "change-this-to-a-random-secret"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    
    # Badge signing
    BADGE_PRIVATE_KEY: str = "generate-ed25519-key-here"
    
    # App
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    APP_NAME: str = "Quantum-Proof Systems Scanner"
    VERSION: str = "1.0.0"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

@lru_cache()
def get_settings() -> Settings:
    return Settings()

settings = get_settings()   