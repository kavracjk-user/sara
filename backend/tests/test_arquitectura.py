"""Reglas de dependencia de la arquitectura (ADR 0001): las capas internas no
conocen a las externas. Si falla, alguien acopló el núcleo a un adaptador."""
import ast
from pathlib import Path

RAIZ = Path(__file__).parent.parent / "sara"

PROHIBIDO = {
    "dominio": ("sara.aplicacion", "sara.adaptadores", "sara.interfaces", "sara.puertos"),
    "puertos": ("sara.aplicacion", "sara.adaptadores", "sara.interfaces"),
    "aplicacion": ("sara.adaptadores", "sara.interfaces"),
}
EXTERNOS = ("prefect", "fastapi", "psycopg", "sqlalchemy", "httpx", "urllib", "requests")


def importados(archivo: Path) -> list[str]:
    arbol = ast.parse(archivo.read_text(encoding="utf-8"))
    salida = []
    for n in ast.walk(arbol):
        if isinstance(n, ast.Import):
            salida += [a.name for a in n.names]
        elif isinstance(n, ast.ImportFrom) and n.module:
            salida.append(n.module)
    return salida


def test_capas_internas_no_dependen_de_las_externas():
    errores = []
    for capa, vetados in PROHIBIDO.items():
        for f in (RAIZ / capa).rglob("*.py"):
            for m in importados(f):
                if m.startswith(vetados):
                    errores.append(f"{f.relative_to(RAIZ)} importa {m}")
    assert not errores, errores


def test_dominio_y_aplicacion_no_usan_librerias_de_infraestructura():
    errores = []
    for capa in ("dominio", "aplicacion", "puertos"):
        for f in (RAIZ / capa).rglob("*.py"):
            for m in importados(f):
                if m.split(".")[0] in EXTERNOS:
                    errores.append(f"{f.relative_to(RAIZ)} importa {m}")
    assert not errores, errores
