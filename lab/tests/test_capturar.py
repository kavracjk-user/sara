"""Captura de alertas: ventanas y consulta (sin Docker)."""
import capturar_alertas as ca


def _m(caso, inicio, fin):
    return {"caso": caso, "inicio_utc": inicio, "fin_utc": fin}


def test_cada_ventana_termina_donde_empieza_el_siguiente_caso():
    ms = [_m("01A", "2026-11-18T05:00:00+00:00", "2026-11-18T05:00:02+00:00"),
          _m("01B", "2026-11-18T05:01:12+00:00", "2026-11-18T05:01:14+00:00")]
    v = ca.ventanas(ms)
    assert v[0][1:] == ("2026-11-18T05:00:00+00:00", "2026-11-18T05:01:12+00:00")
    assert v[1][2] == "2026-11-18T05:02:44+00:00"          # fin + 90 s


def test_consulta_solo_filtra_y_no_escribe():
    q = ca.consulta(["001", "099"], "a", "b")
    filtros = q["query"]["bool"]["filter"]
    assert {"terms": {"agent.id": ["001", "099"]}} in filtros
    assert set(q) == {"size", "sort", "query"}


def test_resumen():
    alertas = [{"rule": {"id": "5760"}, "agent": {"name": "srv-web"}}] * 2
    assert ca.resumir(alertas)["por_agente_regla"] == {"srv-web:5760": 2}
