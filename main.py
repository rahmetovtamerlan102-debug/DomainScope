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
import httpx
import os

app = FastAPI(title="DomainScope API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class DNSInfo(BaseModel):
    a_records: List[str] = []
    aaaa_records: List[str] = []
    ns_records: List[str] = []
    mx_records: List[str] = []
    txt_records: List[str] = []
    spf: Optional[str] = None
    dmarc: Optional[str] = None

class IPInfo(BaseModel):
    provider: Optional[str] = None
    asn: Optional[str] = None
    city: Optional[str] = None
    country: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None

class WhoisInfo(BaseModel):
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    status: List[str] = []

class SSLInfo(BaseModel):
    valid: bool
    issuer: Optional[str] = None
    expires_in_days: Optional[int] = None
    expires_at: Optional[str] = None
    valid_from: Optional[str] = None
    tls_version: Optional[str] = None
    algorithm: Optional[str] = None
    hsts: bool = False

# Убрали поле fix
class VulnInfo(BaseModel):
    severity: str
    title: str
    desc: str

class DomainReport(BaseModel):
    domain: str
    ip_address: Optional[str] = None
    ip_info: Optional[IPInfo] = None
    ssl: SSLInfo
    dns: DNSInfo
    whois: WhoisInfo
    vulns: List[VulnInfo] = []
    scanned_at: str

async def get_headers(domain: str) -> dict:
    try:
        async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
            res = await client.get(f"https://{domain}", timeout=5)
            return dict(res.headers)
    except Exception:
        return {}

def check_vulnerabilities(headers: dict, dns_data: DNSInfo) -> List[VulnInfo]:
    vulns = []
    
    if "content-security-policy" not in headers:
        vulns.append(VulnInfo(
            severity="critical",
            title="Отсутствует Content-Security-Policy (CSP)",
            desc="Отсутствует заголовок CSP. Это снижает уровень защиты от внедрения сторонних скриптов."
        ))

    if "strict-transport-security" not in headers:
        vulns.append(VulnInfo(
            severity="high",
            title="Отсутствует HSTS",
            desc="Заголовок Strict-Transport-Security не настроен. Браузеры могут использовать незащищенное соединение."
        ))

    if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
        vulns.append(VulnInfo(
            severity="medium",
            title="Отсутствует защита от Clickjacking",
            desc="Заголовок X-Frame-Options не задан. Сайт может быть встроен в iframe на сторонних ресурсах."
        ))

    server_header = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    if server_header or powered_by:
        vulns.append(VulnInfo(
            severity="low",
            title="Раскрытие информации о технологиях",
            desc=f"Заголовки раскрывают версию используемого ПО: {server_header} {powered_by}."
        ))

    if not dns_data.dmarc:
        vulns.append(VulnInfo(
            severity="high",
            title="Отсутствует DMARC",
            desc="Нет DMARC записи. Это позволяет отправлять письма от имени домена без проверки подлинности."
        ))

    return vulns

async def get_ip(domain: str) -> Optional[str]:
    try:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, socket.gethostbyname, domain)
    except Exception: return None

async def get_ip_info(ip: str) -> Optional[IPInfo]:
    if not ip: return None
    try:
        async with httpx.AsyncClient() as client:
            res = await client.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,as,lat,lon")
            data = res.json()
            if data.get("status") == "success":
                return IPInfo(provider=data.get("isp"), asn=data.get("as", "").split(" ")[0] if data.get("as") else None, city=data.get("city"), country=data.get("country"), lat=data.get("lat"), lon=data.get("lon"))
    except Exception: pass
    return None

async def get_dns_records(domain: str) -> DNSInfo:
    result = DNSInfo()
    loop = asyncio.get_event_loop()
    def fetch():
        try: result.a_records = [str(r) for r in dns.resolver.resolve(domain, 'A')]
        except Exception: pass
        try: result.aaaa_records = [str(r) for r in dns.resolver.resolve(domain, 'AAAA')]
        except Exception: pass
        try: result.ns_records = [str(r) for r in dns.resolver.resolve(domain, 'NS')]
        except Exception: pass
        try: result.mx_records = [str(r) for r in dns.resolver.resolve(domain, 'MX')]
        except Exception: pass
        txts = []
        try: 
            for r in dns.resolver.resolve(domain, 'TXT'):
                val = str(r).strip('"'); txts.append(val)
                if 'v=spf1' in val: result.spf = val
        except Exception: pass
        try:
            for r in dns.resolver.resolve(f'_dmarc.{domain}', 'TXT'):
                val = str(r).strip('"'); txts.append(val)
                if 'v=DMARC1' in val: result.dmarc = val
        except Exception: pass
        result.txt_records = txts
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
                    valid_from = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (expire_date - datetime.datetime.utcnow()).days
                    issuer = dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown')
                    return SSLInfo(valid=True, issuer=issuer, expires_in_days=days_left, expires_at=expire_date.strftime("%Y-%m-%d"), valid_from=valid_from.strftime("%Y-%m-%d"), tls_version=ssock.version())
        except Exception: return SSLInfo(valid=False)
    return await loop.run_in_executor(None, fetch)

async def get_whois_info(domain: str) -> WhoisInfo:
    loop = asyncio.get_event_loop()
    def fetch():
        try:
            w = whois.whois(domain)
            creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            expiration = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
            status = w.status if isinstance(w.status, list) else [w.status] if w.status else []
            return WhoisInfo(registrar=w.registrar, creation_date=str(creation.date()) if creation else None, expiration_date=str(expiration.date()) if expiration else None, status=status[:5])
        except Exception: return WhoisInfo()
    return await loop.run_in_executor(None, fetch)

@app.get("/api/scan/{domain}", response_model=DomainReport)
async def scan_domain(domain: str):
    clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0].strip().lower()
    if not clean_domain or "." not in clean_domain:
        raise HTTPException(status_code=400, detail="Некорректный домен")

    ip = await get_ip(clean_domain)
    
    ip_info_task = get_ip_info(ip)
    dns_task = get_dns_records(clean_domain)
    ssl_task = get_ssl_info(clean_domain)
    whois_task = get_whois_info(clean_domain)
    headers_task = get_headers(clean_domain)

    ip_info, dns_data, ssl_data, whois_data, headers_data = await asyncio.gather(
        ip_info_task, dns_task, ssl_task, whois_task, headers_task
    )

    vulns_data = check_vulnerabilities(headers_data, dns_data)

    if not ip and not dns_data.a_records and not ssl_data.valid:
        raise HTTPException(status_code=404, detail="Домен не найден или недоступен")

    return DomainReport(
        domain=clean_domain, ip_address=ip, ip_info=ip_info, ssl=ssl_data, dns=dns_data,
        whois=whois_data, vulns=vulns_data, scanned_at=datetime.datetime.now().isoformat()
    )

@app.get("/")
async def serve_frontend():
    if os.path.exists("index.html"):
        return FileResponse("index.html")
    return {"message": "API работает. index.html не найден."}
