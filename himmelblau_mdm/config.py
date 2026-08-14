from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


CloudName = Literal["public", "usgov", "china"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HB_", case_sensitive=False)

    tenant_id: str
    cloud: CloudName = "public"
    managed_identity_client_id: str | None = None
    client_id: str | None = None
    client_secret: SecretStr | None = None
    cosmos_endpoint: str | None = None
    cosmos_database: str = "himmelblau-mdm"
    endpoint_cache_seconds: int = Field(default=3600, ge=60, le=86400)
    graph_cache_seconds: int = Field(default=300, ge=0, le=3600)
    request_timeout_seconds: float = Field(default=15.0, ge=1, le=120)
    max_request_bytes: int = Field(default=1_048_576, ge=16_384, le=10_485_760)
    max_response_bytes: int = Field(default=10_485_760, ge=65_536, le=52_428_800)
    log_level: str = "INFO"
    trusted_intune_suffixes: tuple[str, ...] = ()

    @field_validator("tenant_id")
    @classmethod
    def normalize_tenant(cls, value: str) -> str:
        return value.lower()

    @property
    def authority_host(self) -> str:
        return {
            "public": "login.microsoftonline.com",
            "usgov": "login.microsoftonline.us",
            "china": "login.chinacloudapi.cn",
        }[self.cloud]

    @property
    def graph_origin(self) -> str:
        return {
            "public": "https://graph.microsoft.com",
            "usgov": "https://graph.microsoft.us",
            "china": "https://microsoftgraph.chinacloudapi.cn",
        }[self.cloud]

    @property
    def graph_scope(self) -> str:
        return f"{self.graph_origin}/.default"

    @property
    def issuer_v1(self) -> str:
        return f"https://sts.windows.net/{self.tenant_id}/"

    @property
    def issuer_v2(self) -> str:
        return f"https://{self.authority_host}/{self.tenant_id}/v2.0"

    @property
    def oidc_metadata_url(self) -> str:
        return (
            f"https://{self.authority_host}/{self.tenant_id}"
            "/v2.0/.well-known/openid-configuration"
        )

    @property
    def allowed_intune_suffixes(self) -> tuple[str, ...]:
        defaults = {
            "public": (".manage.microsoft.com",),
            "usgov": (".manage.microsoft.us",),
            "china": (".manage.microsoft.cn",),
        }[self.cloud]
        return self.trusted_intune_suffixes or defaults


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
