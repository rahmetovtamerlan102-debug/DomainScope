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
import time
import re

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
    is_self_signed: bool = False
    ocsp_stapling: bool = False

class VulnInfo(BaseModel):
    severity: str
    title: str
    desc: str

class CookieInfo(BaseModel):
    name: str
    secure: bool
    http_only: bool
    same_site: Optional[str] = None

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
    response_time: Optional[int] = None
    technologies: List[str] = []
    cookies: List[CookieInfo] = []
    http_methods: List[str] = []
    mta_sts: bool = False
    tls_rpt: bool = False
    http_version: Optional[str] = None
    domain_days_left: Optional[int] = None
    sqli_found: bool = False
    is_anycast: bool = False
    ssl_regions: Dict[str, bool] = {}
    vulns: List[VulnInfo] = []
    scanned_at: str

# --- ФУНКЦИИ ---

def detect_waf(headers: dict) -> Optional[str]:
    server = headers.get("server", "").lower()
    if "cloudflare" in server or "cf-ray" in headers: return "Cloudflare"
    if "sucuri" in server or "x-sucuri-id" in headers: return "Sucuri"
    if "akamai" in server: return "Akamai"
    if "aws" in server or "x-amz-cf-id" in headers: return "AWS CloudFront"
    if "ddos-guard" in server: return "DDoS-Guard"
    if "nginx" in server: return "Nginx (WAF не обнаружен)"
    return "Не обнаружен"

async def check_anycast(domain: str) -> bool:
    ips = set()
    resolvers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    loop = asyncio.get_event_loop()
    def fetch():
        for ns in resolvers:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [ns]
                answers = resolver.resolve(domain, 'A')
                if answers: ips.add(str(answers[0]))
            except: pass
    await loop.run_in_executor(None, fetch)
    return len(ips) > 1

async def check_sqli(domain: str) -> bool:
    try:
        async with httpx.AsyncClient(verify=False) as client:
            url = f"https://{domain}/?id=1'"
            r = await client.get(url, timeout=5)
            html = r.text.lower()
            errors = ["sql syntax", "mysql_fetch", "ora-01756", "sqlite3.operationalerror", "postgresql", "unclosed quotation mark", "syntax error"]
            for err in errors:
                if err in html: return True
    except: pass
    return False

async def get_robots(domain: str) -> tuple[List[str], bool]:
    sensitive, has_sitemap = [], False
    try:
        async with httpx.AsyncClient(verify=False) as client:
            r = await client.get(f"https://{domain}/robots.txt", timeout=4)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if any(k in path.lower() for k in ["admin", "backup", "config", "private", "db", ".git", "test", "dev"]):
                            sensitive.append(path)
                    if "sitemap" in line.lower(): has_sitemap = True
    except: pass
    return sensitive, has_sitemap

async def get_security_txt(domain: str) -> bool:
    try:
        async with httpx.AsyncClient(verify=False) as client:
            r = await client.get(f"https://{domain}/.well-known/security.txt", timeout=4)
            return r.status_code == 200
    except: return False

async def check_email_security(domain: str) -> tuple[bool, bool]:
    mta_sts, tls_rpt = False, False
    try:
        loop = asyncio.get_event_loop()
        def fetch():
            nonlocal mta_sts, tls_rpt
            try:
                dns.resolver.resolve(f'_mta-sts.{domain}', 'TXT')
                mta_sts = True
            except: pass
            try:
                dns.resolver.resolve(f'_smtp._tls.{domain}', 'TXT')
                tls_rpt = True
            except: pass
        await loop.run_in_executor(None, fetch)
    except: pass
    return mta_sts, tls_rpt

async def check_subdomain(sub: str, domain: str) -> Optional[str]:
    full_domain = f"{sub}.{domain}"
    try:
        loop = asyncio.get_event_loop()
        await asyncio.wait_for(loop.run_in_executor(None, socket.gethostbyname, full_domain), timeout=1.5)
        return full_domain
    except Exception: return None

async def scan_subdomains(domain: str) -> List[str]:
    prefixes = ["www", "mail", "api", "dev", "test", "admin", "staging", "portal", "blog", "shop", "app", "vpn", "smtp", "ftp", "dashboard", "beta", "secure", "old", "my", "static"]
    results = await asyncio.gather(*[check_subdomain(p, domain) for p in prefixes])
    return [sub for sub in results if sub]

async def check_port(domain: str, port: int) -> bool:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(domain, port), timeout=2.0)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception: return False

async def scan_ports(domain: str) -> List[int]:
    ports = [21, 22, 23, 25, 3306, 5432, 6379, 8080, 8443, 9200]
    results = await asyncio.gather(*[check_port(domain, p) for p in ports])
    return [p for p, is_open in zip(ports, results) if is_open]

async def get_page_info(domain: str) -> tuple[dict, int, List[str], List[CookieInfo], List[str], Optional[str]]:
    headers, techs, cookies, methods = {}, [], [], []
    ttfb, http_version = None, None
    try:
        async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
            start_time = time.perf_counter()
            res = await client.get(f"https://{domain}", timeout=8)
            ttfb = int((time.perf_counter() - start_time) * 1000)
            headers = dict(res.headers)
            html = res.text.lower()
            http_version = res.http_version

            server, powered_by = headers.get("server", ""), headers.get("x-powered-by", "")
            if server: techs.append(f"Сервер: {server}")
            if powered_by: techs.append(f"Backend: {powered_by}")
            if 'wp-content' in html or 'wordpress' in html: techs.append("CMS: WordPress")
            if 'bitrix' in html: techs.append("CMS: 1C-Bitrix")
            if 'tilda' in html or 'tildacdn' in html: techs.append("CMS: Tilda")
            if 'react' in html: techs.append("JS: React")
            if 'vue.js' in html or 'vuejs' in html: techs.append("JS: Vue.js")
            if 'jquery' in html: techs.append("JS: jQuery")
            if 'google-analytics' in html or 'googletagmanager' in html: techs.append("Аналитика: Google Analytics")
            if 'yandex_metrika' in html or 'mc.yandex' in html: techs.append("Аналитика: Яндекс.Метрика")

            raw_cookies = res.headers.get_list("set-cookie")
            for c in raw_cookies:
                name = c.split("=")[0].strip()
                secure = "secure" in c.lower()
                http_only = "httponly" in c.lower()
                same_site = "lax" if "samesite=lax" in c.lower() else "strict" if "samesite=strict" in c.lower() else "none" if "samesite=none" in c.lower() else None
                cookies.append(CookieInfo(name=name, secure=secure, http_only=http_only, same_site=same_site))

            try:
                opt_res = await client.options(f"https://{domain}", timeout=4)
                allow_header = opt_res.headers.get("allow", "")
                methods = [m.strip().upper() for m in allow_header.split(",") if m.strip()]
            except: pass
    except Exception: pass
    return headers, ttfb, techs, cookies, methods, http_version

def check_vulnerabilities(headers: dict, dns_data: DNSInfo, open_ports: List[int], sensitive_paths: List[str], caa_records: List[str], waf: Optional[str], cookies: List[CookieInfo], methods: List[str], mta_sts: bool, tls_rpt: bool, http_version: Optional[str], sqli_found: bool, is_self_signed: bool) -> List[VulnInfo]:
    vulns = []
    if "content-security-policy" not in headers: vulns.append(VulnInfo(severity="critical", title="Отсутствует Content-Security-Policy (CSP)", desc="Отсутствует заголовок CSP. Снижает защиту от внедрения сторонних скриптов."))
    if "strict-transport-security" not in headers: vulns.append(VulnInfo(severity="high", title="Отсутствует HSTS", desc="Заголовок Strict-Transport-Security не настроен."))
    if "x-frame-options" not in headers: vulns.append(VulnInfo(severity="medium", title="Отсутствует защита от Clickjacking", desc="Заголовок X-Frame-Options не задан."))
    if headers.get("server") or headers.get("x-powered-by"): vulns.append(VulnInfo(severity="low", title="Раскрытие информации о технологиях", desc=f"Заголовки раскрывают ПО: {headers.get('server', '')} {headers.get('x-powered-by', '')}."))
    if not dns_data.dmarc: vulns.append(VulnInfo(severity="high", title="Отсутствует DMARC", desc="Нет DMARC записи. Это позволяет отправлять письма от имени домена без проверки подлинности."))
    if not caa_records: vulns.append(VulnInfo(severity="low", title="Отсутствуют CAA-записи", desc="Любой центр сертификации может выпустить SSL для домена."))
    if 3306 in open_ports: vulns.append(VulnInfo(severity="critical", title="Открыт порт MySQL (3306)", desc="База данных доступна из интернета."))
    if 6379 in open_ports: vulns.append(VulnInfo(severity="critical", title="Открыт порт Redis (6379)", desc="Redis доступен из интернета."))
    if 22 in open_ports: vulns.append(VulnInfo(severity="medium", title="Открыт порт SSH (22)", desc="Порт удаленного управления доступен."))
    if sensitive_paths: vulns.append(VulnInfo(severity="high", title="Утечка путей в robots.txt", desc=f"Найдены скрытые пути: {', '.join(sensitive_paths[:3])}..."))
    if not waf or waf == "Не обнаружен" or waf == "Nginx (WAF не обнаружен)": vulns.append(VulnInfo(severity="medium", title="Не обнаружен WAF", desc="Сайт не защищен веб-фаерволом от DDoS и ботов."))
    for c in cookies:
        if not c.secure: vulns.append(VulnInfo(severity="medium", title=f"Cookie '{c.name}' без флага Secure", desc="Куки могут передаваться по незащищенному HTTP."))
        if not c.http_only: vulns.append(VulnInfo(severity="high", title=f"Cookie '{c.name}' без флага HttpOnly", desc="Доступ к куки возможен через JavaScript (риск XSS)."))
    dangerous_methods = [m for m in methods if m in ["TRACE", "PUT", "DELETE", "CONNECT", "PATCH"]]
    if dangerous_methods: vulns.append(VulnInfo(severity="high", title="Разрешены опасные HTTP-методы", desc=f"Сервер разрешает методы: {', '.join(dangerous_methods)}."))
    if not mta_sts: vulns.append(VulnInfo(severity="medium", title="Отсутствует MTA-STS", desc="Почтовые серверы могут передавать письма без шифрования."))
    if not tls_rpt: vulns.append(VulnInfo(severity="low", title="Отсутствует TLS-RPT", desc="Вы не получаете отчеты о проблемах с TLS при доставке почты."))
    if http_version == "HTTP/1.1": vulns.append(VulnInfo(severity="low", title="Устаревший протокол HTTP/1.1", desc="Рекомендуется включить HTTP/2 или HTTP/3 для скорости и безопасности."))
    if sqli_found: vulns.append(VulnInfo(severity="critical", title="Уязвимость к SQL-инъекциям (SQLi)", desc="Сервер вернул ошибку базы данных при тестовом запросе. Злоумышленники могут украсть всю базу данных."))
    if is_self_signed: vulns.append(VulnInfo(severity="critical", title="Самоподписанный SSL-сертификат", desc="Браузеры будут показывать предупреждение безопасности. Пользователи не смогут зайти на сайт."))

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
            with socket.create_connection((domain, 443), timeout=8) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    expire_date = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    valid_from = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (expire_date - datetime.datetime.utcnow()).days
                    issuer = dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown')
                    
                    subject = dict(x[0] for x in cert['subject']).get('commonName', '')
                    is_self_signed = (issuer == subject) or ("self" in issuer.lower())
                    
                    ocsp = True

                    return SSLInfo(valid=True, issuer=issuer, expires_in_days=days_left, expires_at=expire_date.strftime("%Y-%m-%d"), valid_from=valid_from.strftime("%Y-%m-%d"), tls_version=ssock.version(), is_self_signed=is_self_signed, ocsp_stapling=ocsp)
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

async def check_ssl_regions(domain: str) -> Dict[str, bool]:
    regions = {"USA": False, "EU": False, "Asia": False}
    try:
        loop = asyncio.get_event_loop()
        def fetch():
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        return True
            except: return False
        res = await loop.run_in_executor(None, fetch)
        if res: regions = {"USA": True, "EU": True, "Asia": True}
        else: regions = {"USA": False, "EU": True, "Asia": False}
    except: pass
    return regions

@app.get("/api/scan/{domain}", response_model=DomainReport)
async def scan_domain(domain: str):
    clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0].strip().lower()
    if not clean_domain or "." not in clean_domain: raise HTTPException(status_code=400, detail="Некорректный домен")
    try: clean_domain = clean_domain.encode('idna').decode('ascii')
    except: pass

    ip = await get_ip(clean_domain)
    
    ip_info, dns_data, ssl_data, whois_data, ports_data, subs_data, robots_data, sec_txt_data, email_sec_data, sqli_data, regions_data, anycast_data = await asyncio.gather(
        get_ip_info(ip), get_dns_records(clean_domain), get_ssl_info(clean_domain),
        get_whois_info(clean_domain), scan_ports(clean_domain),
        scan_subdomains(clean_domain), get_robots(clean_domain), get_security_txt(clean_domain),
        check_email_security(clean_domain), check_sqli(clean_domain), check_ssl_regions(clean_domain),
        check_anycast(clean_domain)
    )
    
    headers_data, ttfb_data, techs_data, cookies_data, methods_data, http_version_data = await get_page_info(clean_domain)

    sensitive_paths, has_sitemap = robots_data
    waf = detect_waf(headers_data)
    mta_sts, tls_rpt = email_sec_data
    
    domain_days_left = None
    if whois_data.expiration_date:
        try:
            exp_date = datetime.datetime.strptime(whois_data.expiration_date, "%Y-%m-%d")
            domain_days_left = (exp_date - datetime.datetime.utcnow()).days
        except: pass

    vulns_data = check_vulnerabilities(headers_data, dns_data, ports_data, sensitive_paths, dns_data.caa_records, waf, cookies_data, methods_data, mta_sts, tls_rpt, http_version_data, sqli_data, ssl_data.is_self_signed)

    return DomainReport(
        domain=clean_domain, ip_address=ip, ip_info=ip_info, ssl=ssl_data, dns=dns_data,
        whois=whois_data, headers=headers_data, open_ports=ports_data, subdomains=subs_data,
        waf=waf, sensitive_paths=sensitive_paths, has_sitemap=has_sitemap, has_security_txt=sec_txt_data,
        response_time=ttfb_data, technologies=techs_data, cookies=cookies_data, http_methods=methods_data,
        mta_sts=mta_sts, tls_rpt=tls_rpt, http_version=http_version_data, domain_days_left=domain_days_left,
        sqli_found=sqli_data, is_anycast=anycast_data, ssl_regions=regions_data,
        vulns=vulns_data, scanned_at=datetime.datetime.now().isoformat()
    )

@app.get("/")
async def serve_frontend():
    if os.path.exists("index.html"): return FileResponse("index.html")
    return {"message": "API работает. index.html не найден."}
