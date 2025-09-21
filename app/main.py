import os

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import asyncio
from harborscan.scanner import AsyncPortScanner, parse_ports

app = FastAPI()
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # dossier de main.py
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/scan")
async def scan(request: Request):
    form = await request.form()
    target = form.get("target", "127.0.0.1")
    ports_str = form.get("ports", "22,80,443")
    ports = parse_ports(ports_str)

    scanner = AsyncPortScanner(target=target, ports=ports, concurrency=200, timeout=1)
    results = await scanner.scan()

    open_ports = [r for r in results if r["open"]]
    return {"target": target, "results": open_ports}
