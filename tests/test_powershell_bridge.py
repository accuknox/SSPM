"""Unit tests for the PowerShell bridge (powershell_bridge.py)."""

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from sspm.providers.ms365.powershell_bridge import (
    PowerShellBridge,
    PowerShellConfig,
    PowerShellResult,
)


class TestParseOutput:
    """Tests for the pure _parse_output static method — no subprocess needed."""

    def test_valid_batch_payload(self):
        payload = {"result": {"foo": {"a": 1}}, "errors": {}}
        stdout = json.dumps(payload).encode()
        result = PowerShellBridge._parse_output(stdout, b"", 0)
        assert result.ok is True
        assert result.data == payload
        assert result.error is None

    def test_batch_with_per_key_errors(self):
        payload = {"result": {"foo": None}, "errors": {"bar": "cmdlet not found"}}
        stdout = json.dumps(payload).encode()
        result = PowerShellBridge._parse_output(stdout, b"", 0)
        assert result.ok is True
        assert result.data["errors"] == {"bar": "cmdlet not found"}

    def test_non_zero_exit_with_stderr(self):
        result = PowerShellBridge._parse_output(b"", b"Connect-ExchangeOnline failed", 1)
        assert result.ok is False
        assert "exited with code 1" in result.error
        assert result.stderr == "Connect-ExchangeOnline failed"

    def test_empty_stdout(self):
        result = PowerShellBridge._parse_output(b"   \n", b"", 0)
        assert result.ok is False
        assert "no stdout" in result.error

    def test_malformed_json(self):
        result = PowerShellBridge._parse_output(b"{not valid json", b"", 0)
        assert result.ok is False
        assert "Failed to parse" in result.error

    def test_banner_line_before_json_falls_back_to_last_line(self):
        # Connect-MicrosoftTeams writes "Correlation id for this request : …"
        # straight to stdout ahead of our own ConvertTo-Json output.
        payload = {"result": {"foo": "bar"}, "errors": {}}
        stdout = (
            b"Correlation id for this request : 56e2292c-56f4-4e87-8cb7-0177cd83f5ef\n"
            + json.dumps(payload).encode()
        )
        result = PowerShellBridge._parse_output(stdout, b"", 0)
        assert result.ok is True
        assert result.data == payload

    def test_banner_lines_with_still_invalid_json_reports_original_error(self):
        stdout = b"Correlation id for this request : abc\nnot json at all"
        result = PowerShellBridge._parse_output(stdout, b"", 0)
        assert result.ok is False
        assert "Failed to parse" in result.error

    def test_dict_where_array_expected(self):
        # ConvertTo-Json unwrapping a single-element array into a bare object
        # still parses fine here — this is a valid JSON object, just not the
        # shape a caller might expect for a particular key. _parse_output
        # only validates the top-level shape (must be an object).
        stdout = json.dumps([1, 2, 3]).encode()
        result = PowerShellBridge._parse_output(stdout, b"", 0)
        assert result.ok is False
        assert "Expected pwsh JSON output to be an object" in result.error


class TestAvailable:
    def test_available_false_when_pwsh_missing(self):
        bridge = PowerShellBridge(pwsh_path="definitely-not-a-real-executable-xyz")
        assert bridge.available is False

    def test_available_true_when_pwsh_found(self):
        with patch("shutil.which", return_value="/usr/bin/pwsh"):
            bridge = PowerShellBridge(pwsh_path="pwsh")
            assert bridge.available is True

    def test_available_is_cached(self):
        with patch("shutil.which", return_value=None) as mock_which:
            bridge = PowerShellBridge()
            assert bridge.available is False
            assert bridge.available is False
            assert mock_which.call_count == 1


class TestRunScript:
    async def test_not_available_never_spawns(self):
        bridge = PowerShellBridge(pwsh_path="definitely-not-a-real-executable-xyz")
        with patch("asyncio.create_subprocess_exec") as mock_spawn:
            result = await bridge.run_script(Path("/fake/script.ps1"), [])
        mock_spawn.assert_not_called()
        assert result.ok is False
        assert "not found" in result.error

    async def test_successful_run(self):
        payload = {"result": {"foo": "bar"}, "errors": {}}
        fake_process = AsyncMock()
        fake_process.communicate = AsyncMock(
            return_value=(json.dumps(payload).encode(), b"")
        )
        fake_process.returncode = 0

        with patch("shutil.which", return_value="/usr/bin/pwsh"), patch(
            "asyncio.create_subprocess_exec", new=AsyncMock(return_value=fake_process)
        ):
            bridge = PowerShellBridge()
            result = await bridge.run_script(Path("/fake/script.ps1"), ["-Foo", "bar"])

        assert result.ok is True
        assert result.data == payload

    async def test_timeout_kills_process(self):
        fake_process = AsyncMock()

        async def _hang():
            await asyncio.sleep(10)

        fake_process.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
        fake_process.kill = lambda: None
        fake_process.wait = AsyncMock(return_value=None)

        with patch("shutil.which", return_value="/usr/bin/pwsh"), patch(
            "asyncio.create_subprocess_exec", new=AsyncMock(return_value=fake_process)
        ):
            bridge = PowerShellBridge(timeout=0.01)
            result = await bridge.run_script(Path("/fake/script.ps1"), [])

        assert result.ok is False
        assert "timed out" in result.error
        fake_process.wait.assert_awaited()

    async def test_secret_passed_via_env_not_argv(self):
        fake_process = AsyncMock()
        fake_process.communicate = AsyncMock(
            return_value=(json.dumps({"result": {}, "errors": {}}).encode(), b"")
        )
        fake_process.returncode = 0

        captured_kwargs = {}

        async def fake_create_subprocess_exec(*args, **kwargs):
            captured_kwargs["args"] = args
            captured_kwargs["env"] = kwargs.get("env")
            return fake_process

        with patch("shutil.which", return_value="/usr/bin/pwsh"), patch(
            "asyncio.create_subprocess_exec", side_effect=fake_create_subprocess_exec
        ):
            bridge = PowerShellBridge()
            await bridge.run_script(
                Path("/fake/script.ps1"),
                ["-CertificatePath", "/fake/cert.pfx"],
                env_extra={"SSPM_MS365_CERT_PASSWORD": "super-secret"},
            )

        assert "super-secret" not in captured_kwargs["args"]
        assert captured_kwargs["env"]["SSPM_MS365_CERT_PASSWORD"] == "super-secret"

    async def test_spawn_failure_is_captured(self):
        with patch("shutil.which", return_value="/usr/bin/pwsh"), patch(
            "asyncio.create_subprocess_exec",
            side_effect=OSError("permission denied"),
        ):
            bridge = PowerShellBridge()
            result = await bridge.run_script(Path("/fake/script.ps1"), [])

        assert result.ok is False
        assert "Failed to spawn" in result.error


def test_powershell_config_defaults():
    cfg = PowerShellConfig(app_id="app", tenant_id="tenant", cert_path="/cert.pfx")
    assert cfg.enable_exchange is True
    assert cfg.enable_teams is True
    assert cfg.enable_sharepoint is True
    assert cfg.cert_password == ""
