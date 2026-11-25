# API de SARA (fase 4). Imagen oficial de Python con versión fijada.
FROM python:3.13.17-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    PREFECT_HOME=/app/.prefect

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY sara ./sara
# uid 1000: el mismo dueño con que wazuh-certs-tool deja root-ca.pem (modo 0400), para
# leer la CA montada sin ser root ni cambiar sus permisos.
RUN useradd --create-home --uid 1000 sara && mkdir -p /app/.prefect && chown sara /app/.prefect
USER sara

# Dentro del contenedor escucha en todas sus interfaces; Compose lo publica SOLO en
# 127.0.0.1 del equipo (ver docker-compose.yml).
ENV SARA_API_HOST=0.0.0.0 SARA_API_PORT=8000
EXPOSE 8000
CMD ["python", "-m", "sara.interfaces.composicion"]
