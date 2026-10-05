import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent.parent  # project root


class Settings(BaseSettings):
    # Blockchain (Sepolia)
    sepolia_rpc_url: str = ""
    private_key: str = ""
    contract_address: str = ""

    # SQLAlchemy DB — defaults to local SQLite
    database_url: str = "sqlite:///./ironledger.db"

    # Supabase (optional persistence layer — kept from simran's version)
    supabase_url: str = ""
    supabase_key: str = ""

    cors_origins: str = "*"

    model_config = SettingsConfigDict(env_file=str(BASE_DIR / ".env"), extra="ignore")

    @property
    def chain_configured(self) -> bool:
        return bool(self.sepolia_rpc_url and self.private_key and self.contract_address)

    @property
    def supabase_configured(self) -> bool:
        return bool(self.supabase_url and self.supabase_key)

    @property
    def contract_abi_path(self) -> Path:
        return BASE_DIR / "contracts" / "IronLedgerABI.json"


settings = Settings()
