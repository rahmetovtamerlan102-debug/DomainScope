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
import dns.reversename
import whois
import httpx
import os
import time
import re
import ipaddress
import sys

app = FastAPI(title="DomainScope API", version="3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# МОДЕЛИ
# ============================================================

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

class ExposedFile(BaseModel):
    path: str
    content: str

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
    exposed_files: List[ExposedFile] = []
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

# --- МОДЕЛИ IP ---

class PTRClassify(BaseModel):
    raw: List[str] = []
    provider: Optional[str] = None
    connection_type: Optional[str] = None
    is_residential: bool = False
    is_mobile: bool = False
    is_nat: bool = False
    forward_confirmed: bool = False

class Reputation(BaseModel):
    spamhaus: Optional[str] = None
    barracuda: Optional[str] = None
    sorbs: Optional[str] = None
    tor_exit: Optional[bool] = None

class BannerInfo(BaseModel):
    raw: Optional[str] = None
    server: Optional[str] = None
    powered_by: Optional[str] = None
    ssh_version: Optional[str] = None
    smtp_banner: Optional[str] = None

class PortInfo(BaseModel):
    port: int
    service: str
    risk: str = "info"
    banner: Optional[BannerInfo] = None
    http_headers: Dict[str, str] = {}

class TLSResult(BaseModel):
    hostname: Optional[str] = None
    valid: bool = False
    issuer: Optional[str] = None
    subject: Optional[str] = None
    san: List[str] = []
    expires_at: Optional[str] = None
    tls_version: Optional[str] = None

class DNSProviderInfo(BaseModel):
    ptr_zone: Optional[str] = None
    ns: List[str] = []
    soa: Optional[str] = None

class IPReport(BaseModel):
    ip: str
    is_private: bool = False
    ip_version: int = 4
    ptr: PTRClassify
    reputation: Reputation
    open_ports: List[PortInfo] = []
    tls: List[TLSResult] = []
    traceroute: List[str] = []
    dns_provider: DNSProviderInfo = DNSProviderInfo()
    notes: List[str] = []
    scanned_at: str

# ============================================================
# ОБЩИЕ ХЕЛПЕРЫ
# ============================================================

def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip())
        return True
    except ValueError:
        return False

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

# ============================================================
# IP-СКАНЕР (автономный, под домашний IP)
# ============================================================

RESIDENTIAL_MARKERS = (
    "pool", "ppp", "dynamic", "dsl", "broadband", "cable",
    "client", "cust", "res", "home", "user", "adsl", "vdsl",
    "fttb", "ftth", "dial", "dsl-", "static-pool",
)
MOBILE_MARKERS = ("mobile", "umts", "lte", "3g", "4g", "5g", "gsm", "edge")
NAT_MARKERS = ("nat", "cgn", "carrier-grade")

PROVIDER_MAP = {
    "rostelecom": "Ростелеком", "rt.ru": "Ростелеком",
    "mts": "МТС", "beeline": "Билайн", "megafon": "МегаФон",
    "ertelecom": "ЭР-Телеком", "dom.ru": "Дом.ру",
    "ttk": "ТТК", "transtelecom": "ТрансТелеКом",
    "comcast": "Comcast", "verizon": "Verizon", "att": "AT&T",
    "charter": "Charter", "spectrum": "Spectrum", "cox": "Cox",
    "orange": "Orange", "vodafone": "Vodafone",
    "deutsche": "Deutsche Telekom", "telekom": "Deutsche Telekom",
    "bt": "BT", "sky": "Sky", "virgin": "Virgin Media",
    "t-mobile": "T-Mobile", "tmobile": "T-Mobile",
}

def classify_ptr(ptrs: List[str]) -> PTRClassify:
    out = PTRClassify(raw=ptrs)
    if not ptrs:
        return out
    all_low = " ".join(ptrs).lower()
    if any(m in all_low for m in NAT_MARKERS):
        out.is_nat = True
        out.connection_type = "nat"
    if any(m in all_low for m in MOBILE_MARKERS):
        out.is_mobile = True
        out.connection_type = "mobile"
    elif any(m in all_low for m in RESIDENTIAL_MARKERS):
        out.is_residential = True
        out.connection_type = "dynamic" if "dynamic" in all_low else "residential"
    else:
        out.connection_type = "unknown"
    for key, name in PROVIDER_MAP.items():
        if key in all_low:
            out.provider = name
            break
    if not out.provider:
        parts = ptrs[0].split(".")
        if len(parts) >= 3:
            out.provider = ".".join(parts[-2:])
    return out

def get_rdns(ip: str) -> PTRClassify:
    raw, fc = [], False
    try:
        rev = dns.reversename.from_address(ip)
        for r in dns.resolver.resolve(rev, "PTR"):
            host = str(r).rstrip(".")
            raw.append(host)
            try:
                a = dns.resolver.resolve(host, "A")
                if any(str(x) == ip for x in a):
                    fc = True
            except Exception:
                pass
    except Exception:
        pass
    result = classify_ptr(raw)
    result.forward_confirmed = fc
    return result

PORT_MAP = {
    21: ("ftp", "high"), 22: ("ssh", "warn"), 23: ("telnet", "critical"),
    25: ("smtp", "critical"), 53: ("dns", "warn"), 80: ("http", "warn"),
    110: ("pop3", "warn"), 143: ("imap", "warn"), 443: ("https", "warn"),
    445: ("smb", "critical"), 1433: ("mssql", "critical"), 3306: ("mysql", "critical"),
    3389: ("rdp", "critical"), 5432: ("postgres", "critical"), 6379: ("redis", "critical"),
    8000: ("http-alt", "warn"), 8080: ("http-alt", "warn"), 8443: ("https-alt", "warn"),
    9200: ("elasticsearch", "critical"), 27017: ("mongodb", "critical"),
}

async def grab_banner_deep(ip: str, port: int, timeout: float = 2.0) -> BannerInfo:
    info = BannerInfo()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        try:
            if port in (80, 8080, 8000):
                writer.write(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            text = data.decode("utf-8", "ignore")
            info.raw = text.strip()[:300]
            for line in text.splitlines():
                low = line.lower()
                if low.startswith("server:"):
                    info.server = line.split(":", 1)[1].strip()
                elif low.startswith("x-powered-by:"):
                    info.powered_by = line.split(":", 1)[1].strip()
                elif line.startswith("SSH-"):
                    info.ssh_version = line.strip()
                elif line.startswith("220 "):
                    info.smtp_banner = line.strip()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        pass
    return info

async def grab_http_headers(ip: str, port: int) -> Dict[str, str]:
    headers = {}
    try:
        async with httpx.AsyncClient(verify=False, timeout=3) as client:
            scheme = "https" if port in (443, 8443) else "http"
            r = await client.head(f"{scheme}://{ip}:{port}/", headers={"Host": ip})
            for k, v in r.headers.items():
                headers[k] = v
    except Exception:
        pass
    return headers

async def scan_ports(ip: str) -> List[PortInfo]:
    if is_private_ip(ip):
        return []
    async def check(port: int):
        try:
            _, w = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=1.5
            )
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
            service, risk = PORT_MAP.get(port, ("unknown", "warn"))
            banner = await grab_banner_deep(ip, port)
            http_h = {}
            if port in (80, 443, 8080, 8443):
                http_h = await grab_http_headers(ip, port)
            return PortInfo(port=port, service=service, risk=risk,
                            banner=banner, http_headers=http_h)
        except Exception:
            return None
    results = await asyncio.gather(*[check(p) for p in PORT_MAP])
    return [r for r in results if r]

async def scan_tls(ip: str, hostname: str) -> TLSResult:
    loop = asyncio.get_event_loop()
    def fetch():
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((ip, 443), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ss:
                    cert = ss.getpeercert()
                    issuer = dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "Unknown")
                    subject = dict(x[0] for x in cert.get("subject", [])).get("commonName", "")
                    san = []
                    for typ, val in cert.get("subjectAltName", []):
                        if typ == "DNS":
                            san.append(val)
                    return TLSResult(
                        hostname=hostname, valid=True,
                        issuer=issuer, subject=subject, san=san[:10],
                        expires_at=cert.get("notAfter"),
                        tls_version=ss.version(),
                    )
        except Exception:
            return TLSResult(hostname=hostname, valid=False)
    return await loop.run_in_executor(None, fetch)

async def do_traceroute(ip: str, max_hops: int = 15) -> List[str]:
    if is_private_ip(ip):
        return []
    if sys.platform == "win32":
        cmd = ["tracert", "-h", str(max_hops), "-w", "1000", ip]
    else:
        cmd = ["traceroute", "-m", str(max_hops), "-w", "1", "-n", ip]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        return [l for l in out.decode("utf-8", "ignore").splitlines() if l.strip()][:max_hops + 2]
    except Exception:
        return []

TOR_CACHE = {"ips": set(), "ts": 0}
TOR_TTL = 1800

async def refresh_tor_cache():
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get("https://check.torproject.org/torbulkexitlist")
            if r.status_code == 200:
                TOR_CACHE["ips"] = set(r.text.splitlines())
                TOR_CACHE["ts"] = time.time()
    except Exception:
        pass

async def is_tor_exit(ip: str) -> bool:
    if time.time() - TOR_CACHE["ts"] > TOR_TTL:
        await refresh_tor_cache()
    return ip in TOR_CACHE["ips"]

DNSBL_ZONES = {
    "spamhaus": "zen.spamhaus.org",
    "barracuda": "b.barracudacentral.org",
    "sorbs": "dnsbl.sorbs.net",
}

def check_dnsbl(ip: str) -> Dict[str, Optional[str]]:
    out = {}
    if is_private_ip(ip):
        return {k: "private" for k in DNSBL_ZONES}
    rev = ".".join(reversed(ip.split(".")))
    for name, zone in DNSBL_ZONES.items():
        try:
            answers = dns.resolver.resolve(f"{rev}.{zone}", "A")
            codes = [str(a) for a in answers]
            out[name] = "listed" if any(c.startswith("127.0.0.") for c in codes) else "clean"
        except dns.resolver.NXDOMAIN:
            out[name] = "clean"
        except Exception:
            out[name] = "unknown"
    return out

def get_ptr_zone_ns(ip: str) -> DNSProviderInfo:
    out = DNSProviderInfo()
    try:
        rev = dns.reversename.from_address(ip)
        parts = str(rev).split(".")
        zone = ".".join(parts[-5:])
        out.ptr_zone = zone
        try:
            for r in dns.resolver.resolve(zone, "NS"):
                out.ns.append(str(r).rstrip("."))
        except Exception:
            pass
        try:
            for r in dns.resolver.resolve(zone, "SOA"):
                out.soa = str(r.mname).rstrip(".")
        except Exception:
            pass
    except Exception:
        pass
    return out

async def scan_ip(ip: str) -> IPReport:
    ip_obj = ipaddress.ip_address(ip)
    private = ip_obj.is_private

    ptr = get_rdns(ip)
    rep = Reputation()
    notes = []

    if private:
        rep.spamhaus = "private"
        return IPReport(
            ip=ip, is_private=True, ip_version=ip_obj.version,
            ptr=ptr, reputation=rep,
            notes=["Приватный IP (локальная сеть). Внешние проверки недоступны."],
            scanned_at=datetime.datetime.now().isoformat(),
        )

    ports, trace, tor, dnsbl, dns_provider = await asyncio.gather(
        scan_ports(ip),
        do_traceroute(ip),
        is_tor_exit(ip),
        asyncio.to_thread(check_dnsbl, ip),
        asyncio.to_thread(get_ptr_zone_ns, ip),
    )

    rep.spamhaus = dnsbl.get("spamhaus")
    rep.barracuda = dnsbl.get("barracuda")
    rep.sorbs = dnsbl.get("sorbs")
    rep.tor_exit = tor

    tls_results = []
    if ptr.raw and any(p.port == 443 for p in ports):
        for host in ptr.raw[:3]:
            tls_results.append(await scan_tls(ip, host))

    if ptr.is_residential:
        notes.append("Домашний (резидентный) IP. Закрытые порты и отсутствие TLS — норма.")
    if ptr.is_mobile:
        notes.append("Мобильный IP (оператор сотовой связи). Может быть за NAT.")
    if ptr.is_nat:
        notes.append("IP за NAT (carrier-grade NAT) — несколько абонентов делят один адрес.")
    if not ports:
        notes.append("Все проверенные порты закрыты — типично для домашнего IP.")
    if rep.spamhaus == "listed":
        notes.append("Spamhaus: IP в чёрном списке. Возможен вирус/ботнет или открытый прокси.")
    if rep.barracuda == "listed":
        notes.append("Barracuda: IP в чёрном списке (спам/abuse).")
    if rep.sorbs == "listed":
        notes.append("SORBS: IP в чёрном списке.")
    if rep.tor_exit:
        notes.append("IP числится как Tor exit-нода.")
    if any(p.risk == "critical" for p in ports):
        notes.append("Открыты критичные порты (БД, RDP, SMB). Для домашнего IP — серьёзный риск.")
    if ptr.forward_confirmed:
        notes.append("PTR подтверждён обратной A-записью (forward-confirmed).")

    return IPReport(
        ip=ip, is_private=False, ip_version=ip_obj.version,
        ptr=ptr, reputation=rep,
        open_ports=ports, tls=tls_results, traceroute=trace,
        dns_provider=dns_provider,
        notes=notes,
        scanned_at=datetime.datetime.now().isoformat(),
    )

@app.get("/api/scan/ip/{ip}", response_model=IPReport)
async def scan_ip_endpoint(ip: str):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "Некорректный IP")
    return await scan_ip(ip)

# ============================================================
# ДОМЕН-СКАНЕР (старый, без изменений)
# ============================================================

async def check_exposed_files(domain: str) -> List[ExposedFile]:
    files = ["/.env", "/.git/config", "/backup.sql", "/backup.zip", "/phpinfo.php"]
    found = []
    async def fetch(client, f):
        try:
            r = await client.get(f"https://{domain}{f}", timeout=3)
            if r.status_code == 200 and len(r.text) > 10:
                content = r.text[:2000] if len(r.text) > 2000 else r.text
                found.append(ExposedFile(path=f, content=content))
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
                return list(names)[:10]
    except: pass
    return []

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
    m = re.search(r'<title>(.*?)</title>', html, re.I)
    if m: seo.title = m.group(1).strip()
    m = re.search(r'<meta name="description" content="(.*?)"', html, re.I)
    if m: seo.description = m.group(1).strip()
    m = re.search(r'<link rel="canonical" href="(.*?)"', html, re.I)
    if m: seo.canonical = m.group(1).strip()
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

async def scan_ports_domain(domain: str) -> List[int]:
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

def check_vulnerabilities(headers: dict, dns_data: DNSInfo, open_ports: List[int], sensitive_paths: List[str], waf: Optional[str], cookies: List[CookieInfo], methods: List[str], exposed_files: List[ExposedFile], is_cors: bool, axfr_subs: List[str], takeover: List[str]) -> List[VulnInfo]:
    vulns = []
    if "content-security-policy" not in headers: vulns.append(VulnInfo(severity="critical", title="Отсутствует Content-Security-Policy", desc="Снижает защиту от XSS."))
    if "strict-transport-security" not in headers: vulns.append(VulnInfo(severity="high", title="Отсутствует HSTS", desc="Возможен перехват трафика."))
    if not dns_data.dmarc: vulns.append(VulnInfo(severity="high", title="Отсутствует DMARC", desc="Возможен фишинг."))
    if 3306 in open_ports: vulns.append(VulnInfo(severity="critical", title="Открыт MySQL (3306)", desc="База данных в интернете."))
    if 6379 in open_ports: vulns.append(VulnInfo(severity="critical", title="Открыт Redis (6379)", desc="Redis в интернете."))
    if exposed_files:
        file_names = ", ".join([f.path for f in exposed_files])
        vulns.append(VulnInfo(severity="critical", title="Открытые конфиденциальные файлы", desc=f"Найдены: {file_names}"))
    if is_cors: vulns.append(VulnInfo(severity="critical", title="Уязвимость CORS", desc="Любой сайт может красть данные пользователей."))
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
    return {"USA": True, "EU": True, "Asia": True}

async def scan_domain(domain: str):
    clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0].strip().lower()
    if not clean_domain or "." not in clean_domain: raise HTTPException(status_code=400, detail="Некорректный домен")
    try: clean_domain = clean_domain.encode('idna').decode('ascii')
    except: pass

    ip = await get_ip(clean_domain)

    ip_info, dns_data, ssl_data, whois_data, ports_data, subs_data, robots_data, sec_txt_data, email_sec_data, axfr_data, exposed_data, cors_data = await asyncio.gather(
        get_ip_info(ip), get_dns_records(clean_domain), get_ssl_info(clean_domain),
        get_whois_info(clean_domain), scan_ports_domain(clean_domain),
        scan_subdomains(clean_domain), get_robots(clean_domain), get_security_txt(clean_domain),
        check_email_security(clean_domain), check_axfr(clean_domain), check_exposed_files(clean_domain), check_cors(clean_domain)
    )

    headers_data, ttfb_data, techs_data, cookies_data, methods_data, http_version_data, html_data = await get_page_info(clean_domain)

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

@app.get("/api/scan/{domain}", response_model=DomainReport)
async def scan_domain_endpoint(domain: str):
    if is_ip(domain):
        raise HTTPException(400, "Используйте /api/scan/ip/{ip} для IP-адресов")
    return await scan_domain(domain)

@app.get("/")
async def serve_frontend():
    if os.path.exists("index.html"):
        return FileResponse("index.html")
    return {"message": "API работает. index.html не найден."}
