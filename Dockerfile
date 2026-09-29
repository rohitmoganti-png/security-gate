# The Security Gate "toolbox" image: the gate + every scanner + LiteLLM, pinned and verified.
# Used as the machine image of the CodeBuild gate-runner (a GitHub Actions job runs INSIDE it).
#
# Supply chain: base image pinned by digest; gitleaks checked by sha256; every Python package
# installed from a hash-locked file (docker/requirements-*.txt, generated with
# `uv pip compile --generate-hashes`). To upgrade anything: change it in docker/*.in,
# re-lock, rebuild with a NEW ImageTag (ECR tags are immutable).
# Base image from AWS's public mirror of Docker Official Images (ECR Public), not Docker Hub:
# CodeBuild shares IP addresses, so anonymous Docker Hub pulls hit its rate limit (429).
# Same image: the digest is identical on both registries.
FROM public.ecr.aws/docker/library/ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3

ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    SEMGREP_SEND_METRICS=off \
    PATH=/opt/security-gate/venv/bin:$PATH

# OS packages: Python 3.12 (Ubuntu 24.04's own), git + curl + tar (checkout, runner download),
# and the libraries the GitHub Actions runner program needs (ICU, Kerberos, OpenSSL, zlib, LTTng).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-venv ca-certificates curl git tar gzip \
      libicu74 libkrb5-3 libssl3t64 zlib1g liblttng-ust1t64 \
 && rm -rf /var/lib/apt/lists/*

# gitleaks (secrets scanner): download, verify the checksum, install; refuse on mismatch.
RUN curl -fsSL -o /tmp/gitleaks.tgz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
 && echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tgz" | sha256sum -c - \
 && tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks \
 && rm /tmp/gitleaks.tgz

# Three separate Python environments, so the tools' dependencies can never clash.
COPY docker/requirements-*.txt /tmp/req/
RUN python3 -m venv /opt/security-gate/venv \
 && /opt/security-gate/venv/bin/pip install --require-hashes -r /tmp/req/requirements-gate.txt \
 && python3 -m venv /opt/checkov/venv \
 && /opt/checkov/venv/bin/pip install --require-hashes -r /tmp/req/requirements-checkov.txt \
 && ln -s /opt/checkov/venv/bin/checkov /usr/local/bin/checkov \
 && python3 -m venv /opt/litellm/venv \
 && /opt/litellm/venv/bin/pip install --require-hashes -r /tmp/req/requirements-litellm.txt \
 && ln -s /opt/litellm/venv/bin/litellm /usr/local/bin/litellm \
 && rm -rf /tmp/req

# The Security Gate itself (its dependencies are already installed from the lock file above).
COPY pyproject.toml README.md /opt/security-gate/src/
COPY security_gate /opt/security-gate/src/security_gate
RUN /opt/security-gate/venv/bin/pip install --no-deps /opt/security-gate/src

# LiteLLM settings + start-up script (trusted: they come from the tool repo, not from the PR).
COPY litellm-config.yaml /opt/security-gate/litellm-config.yaml
COPY scripts/start-litellm.sh /opt/security-gate/start-litellm.sh

# Fail the image build if any tool is missing or broken.
RUN security-gate --help >/dev/null \
 && gitleaks version \
 && semgrep --version \
 && checkov --version \
 && /opt/litellm/venv/bin/python -c "import litellm" \
 && litellm --help >/dev/null

LABEL org.opencontainers.image.title="security-gate" \
      org.opencontainers.image.description="Security Gate toolbox: gate + gitleaks + semgrep + checkov + LiteLLM"
