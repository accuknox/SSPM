"""
AWS authentication.

Wraps boto3 session creation; supports the standard credential chain
(env vars, ~/.aws/credentials, instance profile) plus explicit credentials.
"""

from __future__ import annotations

import boto3


class AWSAuth:
    """
    Thin wrapper around a boto3 Session.

    Parameters
    ----------
    access_key_id:
        AWS access key ID. If None, the standard boto3 credential chain is used.
    secret_access_key:
        AWS secret access key.
    session_token:
        Optional temporary session token (for STS / assumed roles).
    profile_name:
        Named profile from ~/.aws/credentials.
    region_name:
        Default AWS region. Defaults to ``us-east-1`` for global services.
    """

    def __init__(
        self,
        access_key_id: str | None = None,
        secret_access_key: str | None = None,
        session_token: str | None = None,
        profile_name: str | None = None,
        region_name: str = "us-east-1",
    ) -> None:
        self._region = region_name
        session_kwargs: dict = {"region_name": region_name}
        if profile_name:
            session_kwargs["profile_name"] = profile_name
        if access_key_id and secret_access_key:
            session_kwargs["aws_access_key_id"] = access_key_id
            session_kwargs["aws_secret_access_key"] = secret_access_key
            if session_token:
                session_kwargs["aws_session_token"] = session_token
        self._session = boto3.Session(**session_kwargs)

    def client(self, service: str, region: str | None = None) -> object:
        """Return a low-level boto3 client for *service*."""
        return self._session.client(service, region_name=region or self._region)

    def list_regions(self) -> list[str]:
        """Return all enabled EC2 regions for this account."""
        ec2 = self.client("ec2")
        resp = ec2.describe_regions(Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}])
        return [r["RegionName"] for r in resp.get("Regions", [])]
