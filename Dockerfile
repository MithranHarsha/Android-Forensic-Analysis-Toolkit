# syntax=docker/dockerfile:1
# Android Forensics toolkit — slim, non-root image.
#
#   docker build -t android-forensics .
#   docker run --rm --network none --read-only --tmpfs /tmp \
#       -v "$PWD/evidence:/evidence:ro" -v "$PWD/cases:/cases" \
#       android-forensics analyze /evidence/dump.tar --cases-dir /cases --name case1
#
# Evidence is mounted read-only; only /cases (and the tmpfs) is writable.

FROM python:3.12-slim AS build
WORKDIR /src
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY requirements.lock pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --require-hashes --no-deps -r requirements.lock \
 && /opt/venv/bin/pip install --no-deps .

FROM python:3.12-slim
LABEL org.opencontainers.image.title="android-forensics" \
      org.opencontainers.image.description="Android deleted-data recovery and evidence reconstruction toolkit" \
      org.opencontainers.image.licenses="MIT"
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin forensic \
 && mkdir -p /cases /evidence && chown forensic:forensic /cases
COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER forensic
WORKDIR /cases
VOLUME ["/cases"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s CMD \
  python -c "import android_forensics" || exit 1
ENTRYPOINT ["android-forensics"]
CMD ["--help"]
