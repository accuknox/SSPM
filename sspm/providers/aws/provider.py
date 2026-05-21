"""
AWS provider.

Wires together authentication, data collection, and rule discovery.
"""

from __future__ import annotations

import logging
from typing import Any

from sspm.providers.aws.auth import AWSAuth
from sspm.providers.aws.collector import AWSCollector
from sspm.providers.base import BaseProvider, CollectedData

log = logging.getLogger(__name__)

_BENCHMARK = "CIS Amazon Web Services Foundations Benchmark v7.0.0"


class AWSProvider(BaseProvider):
    """
    Provider for AWS account scanning.

    Parameters
    ----------
    access_key_id:
        AWS access key ID. If None, the standard boto3 credential chain is used
        (environment variables, ~/.aws/credentials, instance profile).
    secret_access_key:
        AWS secret access key. Required if *access_key_id* is set.
    session_token:
        Optional STS session token for temporary credentials.
    profile_name:
        Named profile from ~/.aws/credentials to use.
    region_name:
        Home region for global-service API calls. Defaults to ``us-east-1``.
    account_alias:
        Human-readable label for the scan target (e.g. the account alias or ID).
        Resolved automatically via STS if not provided.
    """

    provider_id = "aws"
    benchmark = _BENCHMARK

    def __init__(
        self,
        access_key_id: str | None = None,
        secret_access_key: str | None = None,
        session_token: str | None = None,
        profile_name: str | None = None,
        region_name: str = "us-east-1",
        account_alias: str = "",
    ) -> None:
        self._auth = AWSAuth(
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            session_token=session_token,
            profile_name=profile_name,
            region_name=region_name,
        )
        self._collector = AWSCollector(self._auth)
        self._account_id = self._resolve_account_id()
        self._account_label = account_alias or self._account_id
        self._autodiscover()

    def _resolve_account_id(self) -> str:
        try:
            sts = self._auth.client("sts")
            return sts.get_caller_identity()["Account"]
        except Exception as exc:  # noqa: BLE001
            log.warning("Could not resolve AWS account ID: %s", exc)
            return "unknown"

    @property
    def target(self) -> str:
        return self._account_label

    async def collect(self) -> CollectedData:
        return await self._collector.collect(self._account_id)

    @staticmethod
    def _autodiscover() -> None:
        from sspm.core.registry import registry
        registry.autodiscover("sspm.providers.aws.rules")
