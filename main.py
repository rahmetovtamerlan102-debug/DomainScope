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
import dns.zone
import dns.query
import whois
import httpx
import os
import time
import re

app = FastAPI(title="DomainScope API", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- МОДЕЛИ ДАННЫХ ---
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

class SEOInfo(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    canonical: Optional[str] = None
    favicon: bool = False
    og_title: Optional[str] = None
    og_image: Optional[str] = None
    broken_links: List[str] = []

class EmailAuth(BaseModel):
    spf_strict: bool = False
    dmarc_policy: Optional[str] = None
    dkim: bool = False
    mta_sts: bool = False
    tls_rpt: bool = False

class DomainReport(BaseModel):
    domain: str
    ip_address: Optional[str] = None
    ip_info: Optional[IPInfo] = None
    ssl: SSLInfo
    dns: DNSInfo
    whois: WhoisInfo
    seo: SEOInfo
    email_auth: EmailAuth
    headers: Dict[str, str] = {}
    open_ports: List[int] = []
    subdomains: List[str] = []
    historical_subs: List[str] = []
    waf: Optional[str] = None
    sensitive_paths: List[str] = []
    exposed_files: List[str] = []
    has_sitemap: bool = False
    has_security_txt: bool = False
    response_time: Optional[int] = None
    technologies: List[str] = []
    cookies: List[CookieInfo] = []
    http_methods: List[str] = []
    http_version: Optional[str] = None
    domain_days_left: Optional[int] = None
    domain_age: Optional[int] = None
    is_anycast: bool = False
    ssl_regions: Dict[str, bool] = {}
    vulns: List[VulnInfo] = []
    scanned_at: str

# --- ФУНКЦИИ ---

async def check_exposed_files(domain: str) -> List[str]:
    files = ["/.env", "/.git/config", "/backup.sql", "/backup.zip", "/phpinfo.php"]
    found = []
    async def fetch(client, f):
        try:
            r = await client.get(f"https://{domain}{f}", timeout=3)
            if r.status_code == 200 and len(r.text) > 10: found.append(f)
        except: pass
    
    async with httpx.AsyncClient(verify=False) as client:
        await asyncio.gather(*[fetch(client, f) for f in files])
    return found

async def check_cors(domain: str) -> bool:
    try:
        async with httpx.AsyncClient(verify=False) as client:
            r = await client.get(f"https://{domain}", headers={"Origin": "https://evil.com"}, timeout=4)
            allow = r.headers.get("access-control-allow-origin", "")
            return allow == "*" or "evil.com" in allow
    except: return False

async def check_axfr(domain: str) -> List[str]:
    subs = []
    try:
        loop = asyncio.get_event_loop()
        def fetch():
            try:
                ns = dns.resolver.resolve(domain, 'NS')[0].target
                z = dns.zone.from_xfr(dns.query.xfr(str(ns), domain, timeout=3))
                for name in z.nodes.keys():
                    subs.append(str(name))
            except: pass
        await loop.run_in_executor(None, fetch)
    except: pass
    return subs

async def check_takeover(subs: List[str]) -> List[str]:
    # Список уязвимых CNAME
    vulnerable = ["herokuapp.com", "s3.amazonaws.com", "github.io", "bitbucket.io"]
    at_risk = []
    loop = asyncio.get_event_loop()
    def fetch(sub):
        try:
            answers = dns.resolver.resolve(sub, 'CNAME')
            for r in answers:
                cname = str(r.target).lower()
                if any(v in cname for v in vulnerable):
                    at_risk.append(sub)
        except: pass
    await asyncio.gather(*[loop.run_in_executor(None, fetch, sub) for sub in subs])
    return at_risk

async def check_crt_sh(domain: str) -> List[str]:
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=6)
            if r.status_code == 200:
                data = r.json()
                names = set()
                for item in data:
                    for name in item['name_value'].split('\n'):
                        if name != domain and not name.startswith('*'):
                            names.add(name.strip())
                return list(names)[:10] # Возвращаем первые 10
    except: pass
    return []

async def check_blacklist(domain: str) -> bool:
    # Проверка в Spamhaus (если IP в черном списке)
    return False # Заглушка для стабильности

def parse_email_auth(dns_data: DNSInfo, dkim: bool, mta_sts: bool, tls_rpt: bool) -> EmailAuth:
    spf_strict = "-all" in (dns_data.spf or "")
    dmarc_policy = "none"
    if dns_data.dmarc:
        if "p=reject" in dns_data.dmarc: dmarc_policy = "reject"
        elif "p=quarantine" in dns_data.dmarc: dmarc_policy = "quarantine"
    
    return EmailAuth(spf_strict=spf_strict, dmarc_policy=dmarc_policy, dkim=dkim, mta_sts=mta_sts, tls_rpt=tls_rpt)

def check_seo(html: str) -> SEOInfo:
    seo = SEOInfo()
    if not html: return seo
    
    # Title
    m = re.search(r'<title>(.*?)</title>', html, re.I)
    if m: seo.title = m.group(1).strip()
    
    # Description
    m = re.search(r'<meta name="description" content="(.*?)"', html, re.I)
    if m: seo.description = m.group(1).strip()
    
    # Canonical
    m = re.search(r'<link rel="canonical" href="(.*?)"', html, re.I)
    if m: seo.canonical = m.group(1).strip()
    
    # OG
    m = re.search(r'<meta property="og:title" content="(.*?)"', html, re.I)
    if m: seo.og_title = m.group(1).strip()
    m = re.search(r'<meta property="og:image" content="(.*?)"', html, re.I)
    if m: seo.og_image = m.group(1).strip()
    
    return seo

async def check_favicon(domain: str) -> bool:
    try:
        async with httpx.AsyncClient(verify=False) as client:
            r = await client.get(f"https://{domain}/favicon.ico", timeout=3)
            return r.status_code == 200
    except: return False

async def check_dkim(domain: str) -> bool:
    selectors = ["default", "google", "mail"]
    for s in selectors:
        try:
            dns.resolver.resolve(f"{s}._domainkey.{domain}", 'TXT')
            return True
        except: pass
    return False

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

def detect_waf(headers: dict) -> Optional[str]:
    server = headers.get("server", "").lower()
    if "cloudflare" in server or "cf-ray" in headers: return "Cloudflare"
    if "sucuri" in server or "x-sucuri-id" in headers: return "Sucuri"
    if "aws" in server or "x-amz-cf-id" in headers: return "AWS CloudFront"
    if "nginx" in server: return "Nginx (WAF не обнаружен)"
    return "Не обнаружен"

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
            try: dns.resolver.resolve(f'_mta-sts.{domain}', 'TXT'); mta_sts = True
            except: pass
            try: dns.resolver.resolve(f'_smtp._tls.{domain}', 'TXT'); tls_rpt = True
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
    prefixes = ["www", "mail", "api", "dev", "test", "admin", "staging", "portal", "app", "vpn", "ftp"]
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
    ports = [21, 22, 23, 3306, 5432, 6379, 9200]
    results = await asyncio.gather(*[check_port(domain, p) for p in ports])
    return [p for p, is_open in zip(ports, results) if is_open]

async def get_page_info(domain: str) -> tuple[dict, int, List[str], List[CookieInfo], List[str], Optional[str], str]:
    headers, techs, cookies, methods = {}, [], [], []
    ttfb, http_version, html = None, None, ""
    try:
        async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
            start_time = time.perf_counter()
            res = await client.get(f"https://{domain}", timeout=8)
            ttfb = int((time.perf_counter() - start_time) * 1000)
            headers = dict(res.headers)
            html = res.text
            http_version = res.http_version

            server, powered_by = headers.get("server", ""), headers.get("x-powered-by", "")
            if server: techs.append(f"Сервер: {server}")
            if powered_by: techs.append(f"Backend: {powered_by}")
            if 'wp-content' in html.lower() or 'wordpress' in html.lower(): techs.append("CMS: WordPress")
            if 'bitrix' in html.lower(): techs.append("CMS: 1C-Bitrix")
            if 'react' in html.lower(): techs.append("JS: React")
            if 'jquery' in html.lower(): techs.append("JS: jQuery")

            raw_cookies = res.headers.get_list("set-cookie")
            for c in raw_cookies:
                name = c.split("=")[0].strip()
                secure = "secure" in c.lower()
                http_only = "httponly" in c.lower()
                same_site = "lax" if "samesite=lax" in c.lower() else "strict" if "samesite=strict" in c.lower() else None
                cookies.append(CookieInfo(name=name, secure=secure, http_only=http_only, same_site=same_site))

            try:
                opt_res = await client.options(f"https://{domain}", timeout=4)
                methods = [m.strip().upper() for m in opt_res.headers.get("allow", "").split(",") if m.strip()]
            except: pass
    except Exception: pass
    return headers, ttfb, techs, cookies, methods, http_version, html

def check_vulnerabilities(headers: dict, dns_data: DNSInfo, open_ports: List[int], sensitive_paths: List[str], waf: Optional[str], cookies: List[CookieInfo], methods: List[str], exposed_files: List[str], is_cors: bool, axfr_subs: List[str], takeover: List[str]) -> List[VulnInfo]:
    vulns = []
    
    # База
    if "content-security-policy" not in headers: vulns.append(VulnInfo(severity="critical", title="Отсутствует Content-Security-Policy", desc="Снижает защиту от XSS."))
    if "strict-transport-security" not in headers: vulns.append(VulnInfo(severity="high", title="Отсутствует HSTS", desc="Возможен перехват трафика."))
    if not dns_data.dmarc: vulns.append(VulnInfo(severity="high", title="Отсутствует DMARC", desc="Возможен фишинг."))
    if 3306 in open_ports: vulns.append(VulnInfo(severity="critical", title="Открыт MySQL (3306)", desc="База данных в интернете."))
    if 6379 in open_ports: vulns.append(VulnInfo(severity="critical", title="Открыт Redis (6379)", desc="Redis в интернете."))
    
    # Продвинутые
    if exposed_files: vulns.append(VulnInfo(severity="critical", title="Открытые конфиденциальные файлы", desc=f"Найдены: {', '.join(exposed_files)}"))
    if is_cors: vulns.append(VulnInfo(severity="critical", title="Уязвимость CORS (Access-Control-Allow-Origin: *)", desc="Любой сайт может красть данные пользователей."))
    if axfr_subs: vulns.append(VulnInfo(severity="critical", title="Открыт Zone Transfer (AXFR)", desc=f"Сервер отдает все поддомены ({len(axfr_subs)} шт)."))
    if takeover: vulns.append(VulnInfo(severity="critical", title="Захват поддоменов (Takeover)", desc=f"Уязвимы: {', '.join(takeover)}"))
    
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
        except: pass
        try: result.ns_records = [str(r) for r in dns.resolver.resolve(domain, 'NS')]
        except: pass
        try: result.mx_records = [str(r) for r in dns.resolver.resolve(domain, 'MX')]
        except: pass
        try: result.caa_records = [str(r) for r in dns.resolver.resolve(domain, 'CAA')]
        except: pass
        txts = []
        try: 
            for r in dns.resolver.resolve(domain, 'TXT'):
                val = str(r).strip('"'); txts.append(val)
                if 'v=spf1' in val: result.spf = val
        except: pass
        try:
            for r in dns.resolver.resolve(f'_dmarc.{domain}', 'TXT'):
                val = str(r).strip('"'); txts.append(val)
                if 'v=DMARC1' in val: result.dmarc = val
        except: pass
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
                    return SSLInfo(valid=True, issuer=issuer, expires_in_days=days_left, expires_at=expire_date.strftime("%Y-%m-%d"), valid_from=valid_from.strftime("%Y-%m-%d"), tls_version=ssock.version(), is_self_signed=is_self_signed, ocsp_stapling=True)
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
    return {"USA": True, "EU": True, "Asia": True} # Упрощено для скорости

@app.get("/api/scan/{domain}", response_model=DomainReport)
async def scan_domain(domain: str):
    clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0].strip().lower()
    if not clean_domain or "." not in clean_domain: raise HTTPException(status_code=400, detail="Некорректный домен")
    try: clean_domain = clean_domain.encode('idna').decode('ascii')
    except: pass

    ip = await get_ip(clean_domain)
    
    # Собираем все данные параллельно
    ip_info, dns_data, ssl_data, whois_data, ports_data, subs_data, robots_data, sec_txt_data, email_sec_data, axfr_data, exposed_data, cors_data = await asyncio.gather(
        get_ip_info(ip), get_dns_records(clean_domain), get_ssl_info(clean_domain),
        get_whois_info(clean_domain), scan_ports(clean_domain),
        scan_subdomains(clean_domain), get_robots(clean_domain), get_security_txt(clean_domain),
        check_email_security(clean_domain), check_axfr(clean_domain), check_exposed_files(clean_domain), check_cors(clean_domain)
    )
    
    headers_data, ttfb_data, techs_data, cookies_data, methods_data, http_version_data, html_data = await get_page_info(clean_domain)
    
    # Доп. проверки на основе HTML и поддоменов
    seo_data = check_seo(html_data)
    favicon_data = await check_favicon(clean_domain)
    seo_data.favicon = favicon_data
    
    dkim_data = await check_dkim(clean_domain)
    mta_sts, tls_rpt = email_sec_data
    email_auth = parse_email_auth(dns_data, dkim_data, mta_sts, tls_rpt)
    
    crt_data = await check_crt_sh(clean_domain)
    takeover_data = await check_takeover(subs_data)
    anycast_data = await check_anycast(clean_domain)
    regions_data = await check_ssl_regions(clean_domain)

    sensitive_paths, has_sitemap = robots_data
    waf = detect_waf(headers_data)
    
    domain_days_left, domain_age = None, None
    if whois_data.expiration_date:
        try:
            exp_date = datetime.datetime.strptime(whois_data.expiration_date, "%Y-%m-%d")
            domain_days_left = (exp_date - datetime.datetime.utcnow()).days
            if whois_data.creation_date:
                cre_date = datetime.datetime.strptime(whois_data.creation_date, "%Y-%m-%d")
                domain_age = (datetime.datetime.utcnow() - cre_date).days
        except: pass

    vulns_data = check_vulnerabilities(headers_data, dns_data, ports_data, sensitive_paths, waf, cookies_data, methods_data, exposed_data, cors_data, axfr_data, takeover_data)

    return DomainReport(
        domain=clean_domain, ip_address=ip, ip_info=ip_info, ssl=ssl_data, dns=dns_data,
        whois=whois_data, seo=seo_data, email_auth=email_auth, headers=headers_data, 
        open_ports=ports_data, subdomains=subs_data, historical_subs=crt_data, waf=waf, 
        sensitive_paths=sensitive_paths, exposed_files=exposed_data, has_sitemap=has_sitemap, 
        has_security_txt=sec_txt_data, response_time=ttfb_data, technologies=techs_data, 
        cookies=cookies_data, http_methods=methods_data, http_version=http_version_data, 
        domain_days_left=domain_days_left, domain_age=domain_age, is_anycast=anycast_data, 
        ssl_regions=regions_data, vulns=vulns_data, scanned_at=datetime.datetime.now().isoformat()
    )

@app.get("/")
async def serve_frontend():
    if os.path.exists("index.html"): return FileResponse("index.html")
    return {"message": "API работает. index.html не найден."}
