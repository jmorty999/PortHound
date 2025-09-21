import asyncio
import pytest
from harborscan.scanner import parse_ports, AsyncPortScanner

# parsing ports
def test_parse_ports_simple():
    """
       Vérifie que parse_ports transforme correctement une chaîne de ports en liste d'entiers.
       Exemple :
           "22,80,1000-1002" -> [22, 80, 1000, 1001, 1002]
       """
    assert parse_ports("22,80,100-102") == [22, 80, 100, 101, 102]
    assert parse_ports("1-3,2,5") == [1, 2, 3, 5]

@pytest.mark.asyncio
#scan mocké asynchro
async def test_scan_mock(monkeypatch):
    """
       Test asynchrone du scanner en mockant les connexions TCP.

       Objectif :
       - Ne pas faire de vraies connexions réseau.
       - Simuler l'ouverture de certains ports et la fermeture des autres.
       - Vérifier que AsyncPortScanner.scan() retourne des résultats corrects.
       """
    async def fake_open_connection(host, port):
        """
                Simule le comportement d'une connexion TCP.
                - Ports 22 et 80 : ouverts, renvoie DummyReader/DummyWriter.
                - Autres ports : lève ConnectionRefusedError (fermés).
                """
        class DummyReader:
            async def read(self, n):
                if port == 22:
                    return b"SSH-2.0-OpenSSH_8.0"
                return b""
        class DummyWriter:
            def write(self, data):
                return None
            async def drain(self):
                return None
            def close(self):
                return None
            async def wait_closed(self):
                return None
        if port in (22, 80):
            return DummyReader(), DummyWriter()
        raise ConnectionRefusedError()
    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    # Création du scanner avec ports 22, 23, 80
    scanner = AsyncPortScanner(target="127.0.0.1", ports=[22, 23, 80], concurrency=2, timeout=0.5)

    # Lancement du scan asynchrone
    results = await scanner.scan()

    # Vérifications :
    # - Doit contenir les 3 ports
    ports = [r["port"] for r in results]
    assert set(ports) == {22, 23, 80}

    # - Port 22 doit être ouvert avec banner SSH
    port22 = next(r for r in results if r["port"] == 22)
    assert port22["open"] is True
    assert port22["banner"] == "SSH-2.0-OpenSSH_8.0"

    # - Port 23 doit être fermé
    port23 = next(r for r in results if r["port"] == 23)
    assert port23["open"] is False
    assert port23["banner"] is None

    # - Port 80 doit être ouvert mais sans banner
    port80 = next(r for r in results if r["port"] == 80)
    assert port80["open"] is True
    assert port80["banner"] is None