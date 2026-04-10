"""
Google Workspace authentication via a service account with domain-wide
delegation (DWD).

The scanner requires a Google Cloud service account that has been granted
domain-wide delegation in the Google Workspace Admin Console.  The service
account key is a JSON file downloaded from the Google Cloud Console.

Required OAuth 2.0 scopes (add all to the DWD configuration):

    https://www.googleapis.com/auth/admin.directory.user.readonly
    https://www.googleapis.com/auth/admin.directory.domain.readonly
    https://www.googleapis.com/auth/admin.directory.orgunit.readonly
    https://www.googleapis.com/auth/admin.directory.group.readonly
    https://www.googleapis.com/auth/admin.reports.audit.readonly
    https://www.googleapis.com/auth/admin.reports.usage.readonly
    https://www.googleapis.com/auth/apps.alerts
    https://www.googleapis.com/auth/apps.groups.settings
    https://www.googleapis.com/auth/gmail.settings.basic

The ``admin_email`` must be a super administrator account that the service
account will impersonate when making API calls.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

import httpx

log = logging.getLogger(__name__)

# Token endpoint for service account JWT exchange
_TOKEN_URL = "https://oauth2.googleapis.com/token"

_SCOPES = [
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.domain.readonly",
    "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    "https://www.googleapis.com/auth/admin.reports.usage.readonly",
    "https://www.googleapis.com/auth/apps.alerts",
    "https://www.googleapis.com/auth/apps.groups.settings",
    # gmail.settings.basic is requested per-user (DWD sub=user_email)
    "https://www.googleapis.com/auth/gmail.settings.basic",
]


class GWSAuth:
    """
    Handles Google Workspace service-account authentication.

    Accepts either a path to a JSON key file or the parsed key dict directly
    (useful for passing credentials via environment variables).
    """

    def __init__(
        self,
        service_account_key: str | dict[str, Any],
        admin_email: str,
        scopes: list[str] | None = None,
    ) -> None:
        if isinstance(service_account_key, str):
            key_path = Path(service_account_key)
            with key_path.open() as fh:
                self._key: dict[str, Any] = json.load(fh)
        else:
            self._key = service_account_key

        self._admin_email = admin_email
        self._scopes = scopes or _SCOPES
        self._token: str | None = None
        self._token_expiry: float = 0.0
        # Per-user token cache for DWD impersonation (user_email → (token, expiry))
        self._user_token_cache: dict[str, tuple[str, float]] = {}

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def get_token(self) -> str:
        """Return a valid access token, refreshing if necessary."""
        if self._token and time.time() < self._token_expiry - 60:
            return self._token
        self._token, self._token_expiry = self._acquire_token_sync()
        return self._token

    async def get_token_async(self) -> str:
        """Async variant — refreshes token if expired."""
        if self._token and time.time() < self._token_expiry - 60:
            return self._token
        self._token, self._token_expiry = await self._acquire_token_async()
        return self._token

    async def get_user_token_async(self, user_email: str) -> str:
        """Return a DWD access token impersonating *user_email* (sub override).

        Used for per-user Gmail settings checks.  Tokens are cached per user
        for the duration of the scan.
        """
        cached = self._user_token_cache.get(user_email)
        if cached and time.time() < cached[1] - 60:
            return cached[0]
        token, expiry = await self._acquire_token_async(sub=user_email)
        self._user_token_cache[user_email] = (token, expiry)
        return token

    @property
    def bearer_header(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.get_token()}"}

    async def bearer_header_async(self) -> dict[str, str]:
        token = await self.get_token_async()
        return {"Authorization": f"Bearer {token}"}

    # ------------------------------------------------------------------
    # JWT / token acquisition
    # ------------------------------------------------------------------

    def _build_jwt(self, sub: str | None = None) -> str:
        """Build a signed JWT assertion for the service account.

        Pass *sub* to impersonate a specific user instead of the admin email
        (used for per-user DWD calls such as Gmail settings checks).
        """
        import base64
        import hashlib
        import hmac
        import json as _json

        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {
            "iss": self._key["client_email"],
            "sub": sub or self._admin_email,
            "scope": " ".join(self._scopes),
            "aud": _TOKEN_URL,
            "iat": now,
            "exp": now + 3600,
        }

        def _b64(data: bytes) -> str:
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

        header_b64 = _b64(_json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = _b64(_json.dumps(payload, separators=(",", ":")).encode())
        signing_input = f"{header_b64}.{payload_b64}".encode()

        # Sign with RSA-SHA256 using the service account private key
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding

            private_key = serialization.load_pem_private_key(
                self._key["private_key"].encode(), password=None
            )
            signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        except ImportError as exc:
            raise RuntimeError(
                "The 'cryptography' package is required for Google Workspace auth. "
                "Install it with: pip install cryptography"
            ) from exc

        sig_b64 = _b64(signature)
        return f"{header_b64}.{payload_b64}.{sig_b64}"

    def _acquire_token_sync(self, sub: str | None = None) -> tuple[str, float]:
        jwt = self._build_jwt(sub=sub)
        resp = httpx.post(
            _TOKEN_URL,
            data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": jwt},
        )
        resp.raise_for_status()
        body = resp.json()
        if "access_token" not in body:
            raise RuntimeError(f"Failed to acquire GWS token: {body}")
        expiry = time.time() + body.get("expires_in", 3600)
        log.debug("GWS access token acquired, expires at %s", expiry)
        return body["access_token"], expiry

    async def _acquire_token_async(self, sub: str | None = None) -> tuple[str, float]:
        jwt = self._build_jwt(sub=sub)
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                _TOKEN_URL,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": jwt,
                },
            )
        resp.raise_for_status()
        body = resp.json()
        if "access_token" not in body:
            raise RuntimeError(f"Failed to acquire GWS token: {body}")
        expiry = time.time() + body.get("expires_in", 3600)
        return body["access_token"], expiry
