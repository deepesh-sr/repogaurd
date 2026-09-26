# RepoGuard image: all scanners bundled, no manual tool installation.
# NOTE: not build-verified on this machine (no Docker); verify with
# `docker build -t repoguard .` on a Docker host before M5 evidence runs.
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends git curl \
 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir "pip-audit==2.10.1" "bandit==1.9.4" "semgrep~=1.90" requests \
 && curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz \
  | tar -xz -C /usr/local/bin gitleaks && chmod +x /usr/local/bin/gitleaks
COPY . /app
RUN pip install --no-cache-dir -e /app && useradd -m repoguard
USER repoguard
WORKDIR /target
ENTRYPOINT ["python", "-m", "repoguard"]
