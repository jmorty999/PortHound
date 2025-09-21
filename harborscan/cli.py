import argparse
import asyncio
import json
import sys
from .scanner import AsyncPortScanner, parse_ports

def build_parser():
    """
        parser argparse pour la CLI.

        Arguments :
        --target       : hostname ou IP de la cible (ex: 127.0.0.1)
        --ports        : liste de ports ou plages (ex: '22,80,1000-1020')
        --concurrency  : nombre max de connexions simultanées
        --timeout      : timeout en secondes pour chaque connexion
        --json         : chemin vers un fichier JSON pour sauvegarder les résultats
        """
    p = argparse.ArgumentParser(description="PortHound / HarborScan - async TCP port scanner (educational)")
    p.add_argument("--target", required=True, help="Hostname ou IP de la cible (ex: 127.0.0.1)")
    p.add_argument("--ports", default="1-1024", help="Liste de ports: '22,80,1000-2000'")
    p.add_argument("--concurrency", type=int, default=500, help="Connexions concurrentes max")
    p.add_argument("--timeout", type=float, default=1.0, help="Timeout par connexion (s)")
    p.add_argument("--json", help="Chemin fichier JSON pour sauvegarder les résultats", default=None)
    return p


def main(argv=None):
    """
        Point d'entrée principal.
        1. Parse les arguments CLI.
        2. Transforme la chaîne de ports en liste d'entiers.
        3. Crée un objet AsyncPortScanner.
        4. Lance le scan asynchrone.
        5. Affiche les ports ouverts et leur banner.
        6. Optionnel : sauvegarde les résultats en JSON.
        """
    argv = argv if argv is not None else sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)

    # parsing ports
    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"Erreur parsing ports: {e}")
        return 2

    #creation scanner
    scanner = AsyncPortScanner(target=args.target, ports=ports, concurrency=args.concurrency, timeout=args.timeout)
    print(f"Target: {args.target} -> {scanner.host_ip}")
    print(f"Scanning {len(ports)} ports (concurrency={args.concurrency}, timeout={args.timeout}s)")

    #début scan
    try:
        results = asyncio.run(scanner.scan())
    except KeyboardInterrupt:
        print("Scan interrompu")
        return 1

    # filtre + affichage ports
    open_ports = [r for r in results if r["open"]]
    for r in sorted(open_ports, key=lambda x: x["port"]):
        print(f"[OPEN] {r['port']}\t{r['banner'] or ''}")

    # sauvegarde json
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"target": args.target, "host_ip": scanner.host_ip, "results": results}, fh, indent=2, ensure_ascii=False)
            print(f"Résultats sauvegardés -> {args.json}")
            return 0

if __name__ == "__main__":
    raise SystemExit(main())