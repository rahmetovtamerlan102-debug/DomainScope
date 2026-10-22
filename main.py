from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List
import asyncio
import socket
import ssl
import datetime
import dns.resolver
import whois
import os

app = FastAPI(title="DomainScope API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- МОДЕЛИ ОТВЕТА ---
class SSLInfo(BaseModel):
    valid: bool
    issuer: Optional[str] = None
    expires_in_days: Optional[int] = None
    expires_at: Optional[str] = None
    tls_version: Optional[str] = None

class DNSInfo(BaseModel):
    a_records: List[str] = []
    ns_records: List[str] = []
    mx_records: List[str] = []
    spf: Optional[str] = None
    dmarc: Optional[str] = None

class WhoisInfo(BaseModel):
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    status: List[str] = []

class DomainReport(BaseModel):
    domain: str
    ip_address: Optional[str] = None
    ssl: SSLInfo
    dns: DNSInfo
    whois: WhoisInfo
    scanned_at: str

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---
async def get_ip(domain: str) -> Optional[str]:
    try:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, socket.gethostbyname, domain)
    except Exception:
        return None

async def get_dns_records(domain: str) -> DNSInfo:
    result = DNSInfo()
    loop = asyncio.get_event_loop()

    def fetch():
        try: result.a_records = [str(r) for r in dns.resolver.resolve(domain, 'A')]
        except Exception: pass
        try: result.ns_records = [str(r) for r in dns.resolver.resolve(domain, 'NS')]
        except Exception: pass
        try: result.mx_records = [str(r) for r in dns.resolver.resolve(domain, 'MX')]
        except Exception: pass
        try:
            for r in dns.resolver.resolve(domain, 'TXT'):
                if 'v=spf1' in str(r): result.spf = str(r).strip('"')
        except Exception: pass
        try:
            for r in dns.resolver.resolve(f'_dmarc.{domain}', 'TXT'):
                if 'v=DMARC1' in str(r): result.dmarc = str(r).strip('"')
        except Exception: pass

    await loop.run_in_executor(None, fetch)
    return result

async def get_ssl_info(domain: str) -> SSLInfo:
    loop = asyncio.get_event_loop()
    def fetch():
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    expire_date = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (expire_date - datetime.datetime.utcnow()).days
                    issuer = dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown')
                    return SSLInfo(valid=True, issuer=issuer, expires_in_days=days_left,
                                   expires_at=expire_date.strftime("%Y-%m-%d"), tls_version=ssock.version())
        except Exception: 
            return SSLInfo(valid=False)
    return await loop.run_in_executor(None, fetch)

async def get_whois_info(domain: str) -> WhoisInfo:
    loop = asyncio.get_event_loop()
    def fetch():
        try:
            w = whois.whois(domain)
            creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            expiration = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
            status = w.status if isinstance(w.status, list) else [w.status] if w.status else []
            return WhoisInfo(registrar=w.registrar,
                             creation_date=str(creation.date()) if creation else None,
                             expiration_date=str(expiration.date()) if expiration else None,
                             status=status[:3])
        except Exception: 
            return WhoisInfo()
    return await loop.run_in_executor(None, fetch)

# --- ЭНДПОИНТЫ ---

@app.get("/api/scan/{domain}", response_model=DomainReport)
async def scan_domain(domain: str):
    clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0].strip().lower()
    
    if not clean_domain or "." not in clean_domain:
        raise HTTPException(status_code=400, detail="Некорректный домен")

    ip, dns_data, ssl_data, whois_data = await asyncio.gather(
        get_ip(clean_domain),
        get_dns_records(clean_domain),
        get_ssl_info(clean_domain),
        get_whois_info(clean_domain)
    )

    if not ip and not dns_data.a_records and not ssl_data.valid:
        raise HTTPException(status_code=404, detail="Домен не найден или недоступен")

    return DomainReport(
        domain=clean_domain, ip_address=ip, ssl=ssl_data, dns=dns_data,
        whois=whois_data, scanned_at=datetime.datetime.now().isoformat()
    )

@app.get("/")
async def serve_frontend():
    if os.path.exists("index.html"):
        return FileResponse("index.html")
    return {"message": "API работает. index.html не найден."}
