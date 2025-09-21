
import asyncio
import socket
from typing import List, Optional, Tuple, Dict, Any

DEFAULT_CONCURRENCY = 500
DEFAULT_TIMEOUT = 1.0

#test port
async def _try_connect(host: str, port: int, timeout: float) -> Tuple[int, bool, Optional[str]]:
    """
        Tente de se connecter au port TCP 'port' de l'hôte 'host'.
        Retourne un tuple (port, is_open, banner)

        Etapes :
        1. Essaie d'ouvrir une connexion TCP asynchrone.
        2. Si succès, envoie un saut de ligne pour déclencher les banners.
        3. Lit jusqu'à 1024 octets pour récupérer un banner éventuel.
        4. Ferme proprement la connexion.
        5. Retourne (port, True, banner) si ouvert, sinon (port, False, None).
        """
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        banner = None
        try:
            writer.write(b"\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=0.35)
            if data:
                banner = data.decode("utf-8", errors="replace").strip()
        except Exception:
            banner = None
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return port, True, banner
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return port, False, None
    except Exception:
        return port, False, None

# Parse ports
def parse_ports(port_str: str) -> List[int]:
    """
        Transforme une chaîne de ports comme '22,80,1000-1005'
        en liste triée d'entiers valides [22, 80, 1000, 1001, 1002, 1003, 1004, 1005]
        """
    ports = set()
    for chunk in port_str.split(','):
        chunk = chunk.strip()
        if not chunk:
            continue
        if '-' in chunk:
            a, b = chunk.split('-', 1)
            try:
                a_i = int(a)
                b_i = int(b)
            except ValueError:
                raise ValueError(f"Invalid port range: {chunk}")
            if a_i > b_i:
                a_i, b_i = b_i, a_i
            ports.update(range(max(1, a_i), min(65535, b_i) + 1))
        else:
            try:
                p = int(chunk)
            except ValueError:
                raise ValueError(f"Invalid port number: {chunk}")
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)

# resolution host
def resolve_host(hostname: str) -> str:
    """
        Résout un nom d'hôte en IP.
        Ex: 'localhost' -> '127.0.0.1'
        """
    try:
        info = socket.getaddrinfo(hostname, None)[0]
        return info[4][0]
    except Exception:
        return hostname

#scanner
class AsyncPortScanner:
    """
        Scanner TCP asynchrone et concurrent.

        Attributs :
        - target : hostname ou IP
        - host_ip : IP résolue
        - ports : liste de ports à scanner
        - concurrency : nombre max de connexions simultanées
        - timeout : timeout par connexion

        Méthodes :
        - _scan_worker(port) : wrapper qui appelle _try_connect pour un port
        - scan() : lance le scan asynchrone de tous les ports
        """
    def __init__(self, target: str, ports: List[int], concurrency: int = DEFAULT_CONCURRENCY, timeout: float = DEFAULT_TIMEOUT):
        self.target = target
        self.host_ip = resolve_host(target)
        self.ports = sorted(set(ports))
        self.concurrency = max(1, concurrency)
        self.timeout = float(timeout)

    #modifier un port unique
    async def _scan_worker(self, port: int) -> Dict[str, Any]:
        """
                Wrapper pour scanner un port unique.
                Retourne un dict : {'port': 22, 'open': True, 'banner': 'SSH...'}
                """
        p, is_open, banner = await _try_connect(self.host_ip, port, self.timeout)
        return {"port": p, "open": is_open, "banner": banner}

    #scan principal
    async def scan(self) -> List[Dict[str, Any]]:
        """
        Scanner tous les ports définis en parallèle.

        Etapes :
        1. Crée un sémaphore pour limiter la concurrence.
        2. Crée une task asyncio pour chaque port.
        3. Attend toutes les tasks et récupère les résultats.
        4. Retourne la liste des dictionnaires pour chaque port testé.
        """

        sem = asyncio.Semaphore(self.concurrency)
        tasks = []
        #limiter la concu
        async def sem_task(p):
            async with sem:
                return await self._scan_worker(p)
        #creation tasks
        for p in self.ports:
            tasks.append(asyncio.create_task(sem_task(p)))
        results = []
        # Parcours tasks dès que finies
        for fut in asyncio.as_completed(tasks):
            res = await fut
            results.append(res)
        return results
