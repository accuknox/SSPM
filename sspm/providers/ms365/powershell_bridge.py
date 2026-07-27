"""
PowerShell bridge for MS365 data that has no Microsoft Graph equivalent.

Exchange Online Management, MicrosoftTeams, and SharePoint Online Management
Shell are Remote PowerShell modules with no Microsoft Graph REST API
equivalent. This module shells out to PowerShell 7 (``pwsh``) to collect
that data as JSON, authenticating app-only via either:

  - a certificate (``PowerShellConfig.cert_path``) — the only option for
    SharePoint Online Management Shell, or
  - a plain OAuth access token acquired with the same client ID/secret
    already used for Microsoft Graph (``PowerShellConfig.client_secret``) —
    supported by Exchange Online Management (``Connect-ExchangeOnline
    -AccessToken``) and MicrosoftTeams (``Connect-MicrosoftTeams
    -AccessTokens``), so no certificate is required for those two modules.

If ``pwsh`` is not installed, or no :class:`PowerShellConfig` is supplied,
callers get ``None``/empty results exactly as before this bridge existed —
this subsystem is entirely additive and opt-in.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

log = logging.getLogger(__name__)

# Client-credentials scopes for the access-token (no-certificate) auth path.
EXO_TOKEN_SCOPE = "https://outlook.office365.com/.default"
GRAPH_TOKEN_SCOPE = "https://graph.microsoft.com/.default"
# "Skype and Teams Tenant Admin API" resource — no API permission needs to
# be configured for this one; configuring it can actually break the token.
TEAMS_TOKEN_SCOPE = "48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default"


async def acquire_client_credentials_token(
    tenant_id: str, client_id: str, client_secret: str, scope: str, timeout: float = 30.0
) -> str:
    """Acquire an app-only access token via the OAuth2 client_credentials grant.

    Raises RuntimeError on any failure (network error, non-2xx response, or a
    response missing ``access_token``) — callers are expected to catch this
    and record it as a per-key collection error rather than letting it
    propagate.
    """
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": scope,
    }
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, data=data)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise RuntimeError(f"Failed to acquire access token for scope {scope!r}: {exc}") from exc

    body = resp.json()
    token = body.get("access_token")
    if not token:
        detail = body.get("error_description", body.get("error", "unknown error"))
        raise RuntimeError(f"Token response for scope {scope!r} missing access_token: {detail}")
    return token


@dataclass
class PowerShellConfig:
    """Auth config shared by all three PowerShell modules.

    Either ``cert_path`` or ``client_secret`` must be set for a module to
    run. ``cert_path`` takes priority when both are present (it is the only
    option SharePoint Online Management Shell supports).
    """

    app_id: str
    tenant_id: str
    cert_path: str = ""
    cert_password: str = ""
    client_secret: str = ""
    organization: str = ""
    sharepoint_admin_url: str = ""
    enable_exchange: bool = True
    enable_teams: bool = True
    enable_sharepoint: bool = True


@dataclass
class PowerShellResult:
    ok: bool
    data: Any | None = None
    error: str | None = None
    stderr: str = ""


class PowerShellBridge:
    """Runs ``.ps1`` scripts via ``pwsh`` and parses their JSON output.

    Every failure mode (pwsh missing, non-zero exit, empty stdout, malformed
    JSON, timeout, spawn error) is captured into a :class:`PowerShellResult`
    with ``ok=False`` — this class never raises.
    """

    def __init__(self, pwsh_path: str = "pwsh", timeout: float = 180.0) -> None:
        self._pwsh_path = pwsh_path
        self._timeout = timeout
        self._available: bool | None = None

    @property
    def available(self) -> bool:
        if self._available is None:
            self._available = shutil.which(self._pwsh_path) is not None
        return self._available

    async def run_script(
        self,
        script_path: Path,
        args: list[str],
        env_extra: dict[str, str] | None = None,
    ) -> PowerShellResult:
        if not self.available:
            return PowerShellResult(
                ok=False,
                error=f"pwsh executable {self._pwsh_path!r} not found on PATH",
            )

        import os

        env = {**os.environ, **(env_extra or {})}
        cmd = [
            self._pwsh_path,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(script_path),
            *args,
        ]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
        except (OSError, FileNotFoundError) as exc:
            return PowerShellResult(ok=False, error=f"Failed to spawn pwsh: {exc}")

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=self._timeout
            )
        except TimeoutError:
            process.kill()
            await process.wait()
            return PowerShellResult(
                ok=False,
                error=f"pwsh script {script_path.name} timed out after {self._timeout}s",
            )

        return self._parse_output(stdout, stderr, process.returncode)

    @staticmethod
    def _parse_output(stdout: bytes, stderr: bytes, returncode: int) -> PowerShellResult:
        stderr_text = stderr.decode("utf-8", errors="replace").strip()

        if returncode != 0:
            return PowerShellResult(
                ok=False,
                error=f"pwsh exited with code {returncode}",
                stderr=stderr_text,
            )

        stdout_text = stdout.decode("utf-8", errors="replace").strip()
        if not stdout_text:
            return PowerShellResult(
                ok=False,
                error="pwsh produced no stdout output",
                stderr=stderr_text,
            )

        try:
            parsed = json.loads(stdout_text)
        except (TypeError, ValueError) as exc:
            # Some modules (e.g. MicrosoftTeams' Connect-MicrosoftTeams) write
            # diagnostic banner lines — "Correlation id for this request : …"
            # — straight to stdout ahead of our own output, bypassing
            # `Out-Null`. Our script always emits its ConvertTo-Json payload
            # as the last line, so fall back to parsing just that.
            last_line = next(
                (line for line in reversed(stdout_text.splitlines()) if line.strip()), ""
            )
            try:
                parsed = json.loads(last_line)
            except (TypeError, ValueError):
                return PowerShellResult(
                    ok=False,
                    error=f"Failed to parse pwsh JSON output: {exc}",
                    stderr=stderr_text,
                )

        if not isinstance(parsed, dict):
            return PowerShellResult(
                ok=False,
                error=f"Expected pwsh JSON output to be an object, got {type(parsed).__name__}",
                stderr=stderr_text,
            )

        return PowerShellResult(ok=True, data=parsed, stderr=stderr_text)
