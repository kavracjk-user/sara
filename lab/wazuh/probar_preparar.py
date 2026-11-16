"""Comprobación rápida de los parches de preparar.py (no necesita Docker ni red).

    python lab/wazuh/probar_preparar.py
"""
import preparar as p

CERTS = """nodes:
  indexer:
    - name: wazuh.indexer
      ip: wazuh.indexer

  server:
    - name: wazuh.manager
      ip: wazuh.manager
"""
WAZUH_YML = """hosts:
  - 1513629884013:
      url: "https://wazuh.manager"
      username: wazuh-wui
      password: "valor-original"
      run_as: true
"""

certs = p.parchear_certs_yml(CERTS)
assert "      ip:\n        - wazuh.indexer\n        - 127.0.0.1\n        - localhost\n\n  server:" in certs
assert "ip: wazuh.manager" in certs            # los otros nodos no cambian

yml = p.parchear_wazuh_yml(WAZUH_YML, "Abc.123*x")
assert '      password: "Abc.123*x"\n      run_as: true' in yml
assert "valor-original" not in yml

usuarios = p.usuarios_internos("$2y$12$aaa", "$2y$12$bbb")
assert usuarios.count("hash:") == 2 and "kibanaro" not in usuarios and "readall" not in usuarios
print("ok: 3 comprobaciones")
