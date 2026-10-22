from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List, Dict
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

# --- МОДЕЛИ ---
class DNSInfo(BaseModel):
    a_records: List[str] = []
    aaaa_records: List[str] = []
    ns_records: List[str] = []
    mx_records: List[str] = []
    txt_records: List[str] = []
    caa_records: List[str] = []
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
    headers: Dict[str, str] = {}
    open_ports: List[int] = []
    subdomains: List[str] = []
    waf: Optional[str] = None
    sensitive_paths: List[str] = []
    has_sitemap: bool = False
    has_security_txt: bool = False
    vulns: List[VulnInfo] = []
    scanned_at: str

# --- НОВЫЕ СКАНЕРЫ (WAF, Robots, Security.txt) ---
def detect_waf(headers: dict) -> Optional[str]:
    server = headers.get("server", "").lower()
    if "cloudflare" in server or "cf-ray" in headers: return "Cloudflare"
    if "sucuri" in server or "x-sucuri-id" in headers: return "Sucuri"
    if "akamai" in server: return "Akamai"
    if "aws" in server or "x-amz-cf-id" in headers: return "AWS CloudFront"
    if "ddos-guard" in server: return "DDoS-Guard"
    if "nginx" in server: return "Nginx (WAF не обнаружен)"
    return "Не обнаружен"

async def get_robots(domain: str) -> tuple[List[str], bool]:
    sensitive = []
    has_sitemap = False
    try:
        async with httpx.AsyncClient(verify=False) as client:
            r = await client.get(f"https://{domain}/robots.txt", timeout=3)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if any(k in path.lower() for k in ["admin", "backup", "config", "private", "db", ".git", "test", "dev"]):
                            sensitive.append(path)
                    if "sitemap" in line.lower():
                        has_sitemap = True
    except: pass
    return sensitive, has_sitemap

async def get_security_txt(domain: str) -> bool:
    try:
        async with httpx.AsyncClient(verify=False) as client:
            r = await client.get(f"https://{domain}/.well-known/security.txt", timeout=3)
            return r.status_code == 200
    except: return False

# --- СКАНЕР ПОДДОМЕНОВ ---
async def check_subdomain(sub: str, domain: str) -> Optional[str]:
    full_domain = f"{sub}.{domain}"
    try:
        loop = asyncio.get_event_loop()
        await asyncio.wait_for(loop.run_in_executor(None, socket.gethostbyname, full_domain), timeout=1.0)
        return full_domain
    except Exception:
        return None

async def scan_subdomains(domain: str) -> List[str]:
    prefixes = ["www", "mail", "api", "dev", "test", "admin", "staging", "portal", "blog", "shop", "app", "vpn", "smtp", "ftp", "dashboard", "beta", "secure", "old", "my", "static"]
    tasks = [check_subdomain(p, domain) for p in prefixes]
    results = await asyncio.gather(*tasks)
    return [sub for sub in results if sub]

# --- СКАНЕР ПОРТОВ ---
async def check_port(domain: str, port: int) -> bool:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(domain, port), timeout=0.5)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False

async def scan_ports(domain: str) -> List[int]:
    ports = [21, 22, 23, 25, 3306, 5432, 6379, 8080, 8443, 9200]
    results = await asyncio.gather(*[check_port(domain, p) for p in ports])
    return [p for p, is_open in zip(ports, results) if is_open]

# --- ЗАГОЛОВКИ И УЯЗВИМОСТИ ---
async def get_headers(domain: str) -> dict:
    try:
        async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
            res = await client.get(f"https://{domain}", timeout=5)
            return dict(res.headers)
    except Exception:
        return {}

def check_vulnerabilities(headers: dict, dns_data: DNSInfo, open_ports: List[int], sensitive_paths: List[str], caa_records: List[str], waf: Optional[str]) -> List[VulnInfo]:
    vulns = []
    if "content-security-policy" not in headers:
        vulns.append(VulnInfo(severity="critical", title="Отсутствует Content-Security-Policy (CSP)", desc="Отсутствует заголовок CSP. Снижает защиту от внедрения сторонних скриптов (XSS)."))
    if "strict-transport-security" not in headers:
        vulns.append(VulnInfo(severity="high", title="Отсутствует HSTS", desc="Заголовок Strict-Transport-Security не настроен."))
    if "x-frame-options" not in headers:
        vulns.append(VulnInfo(severity="medium", title="Отсутствует защита от Clickjacking", desc="Заголовок X-Frame-Options не задан."))
    if headers.get("server") or headers.get("x-powered-by"):
        vulns.append(VulnInfo(severity="low", title="Раскрытие информации о технологиях", desc=f"Заголовки раскрывают ПО: {headers.get('server', '')} {headers.get('x-powered-by', '')}."))
    if not dns_data.dmarc:
        vulns.append(VulnInfo(severity="high", title="Отсутствует DMARC", desc="Нет DMARC записи. Это позволяет отправлять письма от имени домена без проверки подлинности."))
    if 3306 in open_ports: vulns.append(VulnInfo(severity="critical", title="Открыт порт MySQL (3306)", desc="База данных доступна из интернета."))
    if 6379 in open_ports: vulns.append(VulnInfo(severity="critical", title="Открыт порт Redis (6379)", desc="Redis доступен из интернета."))
    if 22 in open_ports: vulns.append(VulnInfo(severity="medium", title="Открыт порт SSH (22)", desc="Порт удаленного управления доступен."))
    
    # Новые проверки
    if sensitive_paths:
        vulns.append(VulnInfo(severity="high", title="Утечка путей в robots.txt", desc=f"Найдены скрытые пути: {', '.join(sensitive_paths[:3])}..."))
    if not caa_records:
        vulns.append(VulnInfo(severity="low", title="Отсутствуют CAA-записи", desc="Любой центр сертификации может выпустить SSL для домена."))
    if not waf or waf == "Не обнаружен" or waf == "Nginx (WAF не обнаружен)":
        vulns.append(VulnInfo(severity="medium", title="Не обнаружен WAF", desc="Сайт не защищен веб-фаерволом от DDoS и ботов."))

    return vulns

# --- БАЗОВЫЕ СКАНЕРЫ ---
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
        try: result.caa_records = [str(r) for r in dns.resolver.resolve(domain, 'CAA')]
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

# --- ЭНДПОИНТ ---
@app.get("/api/scan/{domain}", response_model=DomainReport)
async def scan_domain(domain: str):
    clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0].strip().lower()
    if not clean_domain or "." not in clean_domain:
        raise HTTPException(status_code=400, detail="Некорректный домен")

    ip = await get_ip(clean_domain)
    
    # Запускаем все задачи параллельно
    ip_info, dns_data, ssl_data, whois_data, headers_data, ports_data, subs_data, robots_data, sec_txt_data = await asyncio.gather(
        get_ip_info(ip), get_dns_records(clean_domain), get_ssl_info(clean_domain),
        get_whois_info(clean_domain), get_headers(clean_domain), scan_ports(clean_domain),
        scan_subdomains(clean_domain), get_robots(clean_domain), get_security_txt(clean_domain)
    )

    sensitive_paths, has_sitemap = robots_data
    waf = detect_waf(headers_data)

    vulns_data = check_vulnerabilities(headers_data, dns_data, ports_data, sensitive_paths, dns_data.caa_records, waf)

    return DomainReport(
        domain=clean_domain, ip_address=ip, ip_info=ip_info, ssl=ssl_data, dns=dns_data,
        whois=whois_data, headers=headers_data, open_ports=ports_data, subdomains=subs_data,
        waf=waf, sensitive_paths=sensitive_paths, has_sitemap=has_sitemap, has_security_txt=sec_txt_data,
        vulns=vulns_data, scanned_at=datetime.datetime.now().isoformat()
    )

@app.get("/")
async def serve_frontend():
    if os.path.exists("index.html"):
        return FileResponse("index.html")
    return {"message": "API работает. index.html не найден."}
