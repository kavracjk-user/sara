"""Escribe el contrato OpenAPI de la API en docs/api/openapi.json (sin servicios).

Uso, desde backend/:  .venv/Scripts/python scripts/exportar_openapi.py
La prueba tests/test_api.py::test_openapi_al_dia falla si el archivo quedó desactualizado.
"""
import json
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(RAIZ / "backend"))

from sara.interfaces.api import ConfiguracionAPI, crear_app  # noqa: E402

DESTINO = RAIZ / "docs" / "api" / "openapi.json"


def contrato() -> str:
    app = crear_app(ConfiguracionAPI(servicio=None, clave_api=None))  # type: ignore[arg-type]
    return json.dumps(app.openapi(), ensure_ascii=False, indent=2) + "\n"


if __name__ == "__main__":
    DESTINO.write_text(contrato(), encoding="utf-8", newline="\n")
    print(f"Escrito {DESTINO.relative_to(RAIZ)}")
