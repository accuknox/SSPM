# syntax = docker/dockerfile:1.6

FROM mcr.microsoft.com/powershell:7.4-debian-12

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3.11 \
        python3.11-venv \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pwsh -NoProfile -NonInteractive -Command " \
        \$ErrorActionPreference = 'Stop'; \
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted; \
        Install-Module -Name ExchangeOnlineManagement -Scope AllUsers -Force -AcceptLicense; \
        Install-Module -Name MicrosoftTeams -Scope AllUsers -Force -AcceptLicense; \
        Install-Module -Name Microsoft.Online.SharePoint.PowerShell -Scope AllUsers -Force -AcceptLicense; \
    "

WORKDIR /app

# hadolint ignore=DL3008,DL3015,DL3009
RUN apt-get update -y \
    && apt-get install --no-install-recommends -y curl git python3-pip wget unzip \
    && rm -rf /var/lib/apt/lists/*

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN python3.11 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip

ENV PATH="/opt/venv/bin:${PATH}"

# Fetch the tagged release from GitHub (not the local working tree) and
# install it into the venv — pyproject.toml is the only manifest this
# project has, there is no requirements.txt.
# hadolint ignore=DL3003
RUN wget -q -O sspm.zip https://github.com/accuknox/SSPM/archive/refs/tags/alpha-v4.zip \
    && unzip -q sspm.zip \
    && pip3 install --no-cache-dir ./SSPM-alpha-v4 \
    && rm -rf sspm.zip SSPM-alpha-v4

ENTRYPOINT [ "/bin/bash" ]
