"""Parches de texto de preparar.py (no necesita Docker ni red)."""
import preparar as p

WAZUH_YML = """hosts:
  - 1513629884013:
      url: "https://wazuh.manager"
      username: wazuh-wui
      password: "valor-original"
      run_as: true
"""



def test_clave_de_la_api_en_wazuh_yml():
    yml = p.parchear_wazuh_yml(WAZUH_YML, "Abc.123*x")
    assert '      password: "Abc.123*x"\n      run_as: true' in yml
    assert "valor-original" not in yml


def test_solo_admin_y_kibanaserver():
    usuarios = p.usuarios_internos("$2y$12$aaa", "$2y$12$bbb")
    assert usuarios.count("hash:") == 2 and "kibanaro" not in usuarios and "readall" not in usuarios


def test_clona_sin_convertir_a_crlf():
    cmd = p.comando_clonar()
    assert cmd[:5] == ["git", "-c", "core.autocrlf=false", "-c", "core.eol=lf"]
    assert f"v{p.VERSION_WAZUH}" in cmd


def test_escribe_con_lf(tmp_path):
    ruta = tmp_path / "x.yml"
    p.escribir_lf(ruta, "a: 1\nb: 2\n")
    assert ruta.read_bytes() == b"a: 1\nb: 2\n"
