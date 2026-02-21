# ═══════════════════════════════════════════════════════════════════════════════
# attacker — Demo / Jupyter container
# Runs as non-root (UID 1002). Kept minimal — only requests + rich.
# ═══════════════════════════════════════════════════════════════════════════════

FROM python:3.11-slim

# Create non-root user (UID/GID 1002)
RUN groupadd -r -g 1002 attacker \
 && useradd  -r -u 1002 -g attacker -d /workspace -s /sbin/nologin attacker

WORKDIR /workspace

RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir requests==2.32.3 rich==13.9.4

COPY --chown=attacker:attacker . /workspace/demos/

USER attacker

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

CMD ["tail", "-f", "/dev/null"]
