from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import asyncio
import socket
import ssl
import datetime
import dns.resolver
import whois

app = FastAPI(title="DomainScope API", version="1.0")

# Разрешаем CORS для локальной разработки (фронт на другом порту)
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
        info = await loop.run_in_executor(None, socket.gethostbyname, domain)
        return info
    except Exception:
        return None

async def get_dns_records(domain: str) -> DNSInfo:
    result = DNSInfo()
    loop = asyncio.get_event_loop()

    def fetch():
        try:
            result.a_records = [str(r) for r in dns.resolver.resolve(domain, 'A')]
        except: pass
        try:
            result.ns_records = [str(r) for r in dns.resolver.resolve(domain, 'NS')]
        except: pass
        try:
            result.mx_records = [str(r) for r in dns.resolver.resolve(domain, 'MX')]
        except: pass
        try:
            txt = dns.resolver.resolve(domain, 'TXT')
            for r in txt:
                if 'v=spf1' in str(r): result.spf = str(r)
        except: pass
        try:
            dmarc = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for r in dmarc:
                if 'v=DMARC1' in str(r): result.dmarc = str(r)
        except: pass
    
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
                    tls_ver = ssock.version()
                    
                    expire_str = cert['notAfter']
                    # Формат даты из сертификата: 'Jan  1 00:00:00 2027 GMT'
                    expire_date = datetime.datetime.strptime(expire_str, '%b %d %H:%M:%S %Y %Z')
                    now = datetime.datetime.utcnow()
                    days_left = (expire_date - now).days
                    
                    issuer_dict = dict(x[0] for x in cert['issuer'])
                    issuer = issuer_dict.get('organizationName', 'Unknown')
                    
                    return SSLInfo(
                        valid=True,
                        issuer=issuer,
                        expires_in_days=days_left,
                        expires_at=expire_date.strftime("%Y-%m-%d"),
                        tls_version=tls_ver
                    )
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
            
            return WhoisInfo(
                registrar=w.registrar,
                creation_date=str(creation.date()) if creation else None,
                expiration_date=str(expiration.date()) if expiration else None,
                status=status[:3]
            )
        except Exception:
            return WhoisInfo()
    return await loop.run_in_executor(None, fetch)

# --- ЭНДПОИНТЫ ---

@app.get("/api/scan/{domain}", response_model=DomainReport)
async def scan_domain(domain: str):
    # Очищаем домен
    clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0].strip()

    ip_task = get_ip(clean_domain)
    dns_task = get_dns_records(clean_domain)
    ssl_task = get_ssl_info(clean_domain)
    whois_task = get_whois_info(clean_domain)

    ip, dns_data, ssl_data, whois_data = await asyncio.gather(
        ip_task, dns_task, ssl_task, whois_task
    )

    if not ip and not dns_data.a_records and not ssl_data.valid:
        raise HTTPException(status_code=404, detail="Домен не найден или недоступен")

    return DomainReport(
        domain=clean_domain,
        ip_address=ip,
        ssl=ssl_data,
        dns=dns_data,
        whois=whois_data,
        scanned_at=datetime.datetime.now().isoformat()
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
