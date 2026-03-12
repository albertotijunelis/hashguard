"""IOC enrichment for HashGuard v2.

Expands IOCs with additional context:
- Passive DNS lookups (forward + reverse)
- IP geolocation (ip-api.com — free, 45 req/min)
- AbuseIPDB reputation (with API key)
- URLhaus malicious URL check
- WHOIS registration data
- Domain age calculation
"""

import socket
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from hashguard.logger import get_logger

logger = get_logger(__name__)

try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class EnrichedIOC:
    value: str
    ioc_type: str
    enrichments: Dict[str, str] = field(default_factory=dict)
    reputation: str = "unknown"  # clean, suspicious, malicious, unknown
    tags: List[str] = field(default_factory=list)


@dataclass
class EnrichmentResult:
    enriched: List[EnrichedIOC] = field(default_factory=list)
    total_enriched: int = 0

    def to_dict(self) -> dict:
        return {
            "enriched": [
                {
                    "value": e.value,
                    "type": e.ioc_type,
                    "enrichments": e.enrichments,
                    "reputation": e.reputation,
                    "tags": e.tags,
                }
                for e in self.enriched
            ],
            "total_enriched": self.total_enriched,
        }


# ── DNS lookups ──────────────────────────────────────────────────────────────


def _resolve_dns(domain: str) -> Dict[str, str]:
    """Resolve domain to IPs."""
    result = {}
    try:
        ips = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        resolved = list(set(addr[4][0] for addr in ips))
        if resolved:
            result["resolved_ips"] = ", ".join(resolved[:5])
    except socket.gaierror:
        result["dns_status"] = "NXDOMAIN"
    except Exception:
        pass
    return result


def _reverse_dns(ip: str) -> Dict[str, str]:
    """Reverse DNS lookup."""
    result = {}
    try:
        hostname = socket.gethostbyaddr(ip)
        result["reverse_dns"] = hostname[0]
    except (socket.herror, socket.gaierror):
        result["reverse_dns"] = "none"
    except Exception:
        pass
    return result


# ── IP geolocation ───────────────────────────────────────────────────────────


def _query_ip_api(ip: str) -> Dict[str, str]:
    """Free IP geolocation via ip-api.com (45 req/min)."""
    if not HAS_REQUESTS:
        return {}
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,query",
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country", ""),
                    "city": data.get("city", ""),
                    "isp": data.get("isp", ""),
                    "org": data.get("org", ""),
                    "asn": data.get("as", ""),
                }
    except Exception:
        pass
    return {}


# ── AbuseIPDB ────────────────────────────────────────────────────────────────


def _query_abuseipdb(ip: str, api_key: str = "") -> Dict[str, str]:
    """Query AbuseIPDB for IP reputation (requires free API key)."""
    if not HAS_REQUESTS or not api_key:
        return {}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            timeout=8,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            return {
                "abuse_score": str(data.get("abuseConfidenceScore", "")),
                "total_reports": str(data.get("totalReports", "")),
                "last_reported": data.get("lastReportedAt", ""),
                "usage_type": data.get("usageType", ""),
            }
    except Exception:
        pass
    return {}


# ── URLhaus ──────────────────────────────────────────────────────────────────


def _query_urlhaus_host(host: str) -> Dict[str, str]:
    """Check a domain/IP against URLhaus (free, no key needed)."""
    if not HAS_REQUESTS:
        return {}
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": host},
            timeout=8,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "no_results":
                return {"urlhaus": "clean"}
            count = data.get("urls_online", 0)
            if count:
                return {
                    "urlhaus": "malicious",
                    "urlhaus_urls_online": str(count),
                    "urlhaus_reference": data.get("urlhaus_reference", ""),
                }
            return {"urlhaus": "listed (offline)"}
    except Exception:
        pass
    return {}


# ── WHOIS (lightweight, stdlib-only) ─────────────────────────────────────────


def _whois_lookup(domain: str) -> Dict[str, str]:
    """Simple WHOIS lookup via socket to whois servers."""
    result = {}
    try:
        # Get TLD-specific WHOIS server
        tld = domain.rsplit(".", 1)[-1]
        whois_server = f"{tld}.whois-servers.net"

        sock = socket.create_connection((whois_server, 43), timeout=5)
        sock.sendall((domain + "\r\n").encode())
        raw = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
        sock.close()

        text = raw.decode("utf-8", errors="ignore")

        # Parse key fields
        for line in text.splitlines():
            line_low = line.lower().strip()
            if line_low.startswith("registrar:"):
                result["registrar"] = line.split(":", 1)[1].strip()[:80]
            elif line_low.startswith("creation date:") or line_low.startswith("created:"):
                created = line.split(":", 1)[1].strip()[:30]
                result["created"] = created
                # Calculate domain age
                try:
                    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d", "%d-%b-%Y"):
                        try:
                            dt = datetime.strptime(created[:19], fmt)
                            age_days = (datetime.now() - dt).days
                            result["domain_age_days"] = str(age_days)
                            break
                        except ValueError:
                            continue
                except Exception:
                    pass
            elif line_low.startswith("registrant country:"):
                result["registrant_country"] = line.split(":", 1)[1].strip()[:30]
            elif line_low.startswith("name server:") and "name_servers" not in result:
                result["name_servers"] = line.split(":", 1)[1].strip()[:80]

    except Exception:
        pass
    return result


# ── Per-IOC enrichment functions ─────────────────────────────────────────────


def enrich_ip(ip: str, abuseipdb_key: str = "") -> EnrichedIOC:
    """Enrich an IP address with all available information."""
    enriched = EnrichedIOC(value=ip, ioc_type="ip")
    enriched.enrichments.update(_reverse_dns(ip))
    enriched.enrichments.update(_query_ip_api(ip))
    enriched.enrichments.update(_query_urlhaus_host(ip))

    if abuseipdb_key:
        abuse = _query_abuseipdb(ip, abuseipdb_key)
        enriched.enrichments.update(abuse)
        score = int(abuse.get("abuse_score", 0) or 0)
        if score >= 80:
            enriched.reputation = "malicious"
        elif score >= 25:
            enriched.reputation = "suspicious"

    if enriched.enrichments.get("urlhaus") == "malicious":
        enriched.reputation = "malicious"
        enriched.tags.append("urlhaus-listed")

    return enriched


def enrich_domain(domain: str) -> EnrichedIOC:
    """Enrich a domain with DNS, WHOIS, and reputation data."""
    enriched = EnrichedIOC(value=domain, ioc_type="domain")
    enriched.enrichments.update(_resolve_dns(domain))
    enriched.enrichments.update(_whois_lookup(domain))
    enriched.enrichments.update(_query_urlhaus_host(domain))

    # Reputation heuristics
    if enriched.enrichments.get("urlhaus") == "malicious":
        enriched.reputation = "malicious"
        enriched.tags.append("urlhaus-listed")
    elif enriched.enrichments.get("dns_status") == "NXDOMAIN":
        enriched.tags.append("nxdomain")
    else:
        age = enriched.enrichments.get("domain_age_days")
        if age and int(age) < 30:
            enriched.reputation = "suspicious"
            enriched.tags.append("newly-registered")

    return enriched


def enrich_url(url: str) -> EnrichedIOC:
    """Enrich a URL against URLhaus."""
    enriched = EnrichedIOC(value=url, ioc_type="url")
    if not HAS_REQUESTS:
        return enriched
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=8,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "no_results":
                enriched.enrichments["urlhaus"] = "clean"
            else:
                enriched.reputation = "malicious"
                enriched.enrichments["urlhaus"] = "malicious"
                enriched.enrichments["threat"] = data.get("threat", "")
                enriched.tags.append("urlhaus-listed")
    except Exception:
        pass
    return enriched


def enrich_iocs(iocs: Dict[str, List[str]], max_per_type: int = 5) -> EnrichmentResult:
    """Enrich all IOCs from an analysis result."""
    result = EnrichmentResult()
    tasks = []

    ips = iocs.get("ip_addresses", [])[:max_per_type]
    domains = iocs.get("domains", [])[:max_per_type]
    urls = iocs.get("urls", [])[:max_per_type]

    with ThreadPoolExecutor(max_workers=4) as executor:
        for ip in ips:
            tasks.append(executor.submit(enrich_ip, ip))
        for domain in domains:
            tasks.append(executor.submit(enrich_domain, domain))
        for url in urls:
            tasks.append(executor.submit(enrich_url, url))

        for future in as_completed(tasks):
            try:
                enriched = future.result()
                result.enriched.append(enriched)
            except Exception:
                pass

    # Enrich other IOCs with basic info (no network calls)
    for wallet in iocs.get("crypto_wallets", [])[:max_per_type]:
        e = EnrichedIOC(value=wallet, ioc_type="wallet")
        if wallet.startswith("1") or wallet.startswith("3") or wallet.startswith("bc1"):
            e.tags.append("bitcoin")
        elif wallet.startswith("0x"):
            e.tags.append("ethereum")
        elif len(wallet) > 90:
            e.tags.append("monero")
        result.enriched.append(e)

    for email in iocs.get("emails", [])[:max_per_type]:
        e = EnrichedIOC(value=email, ioc_type="email")
        domain_part = email.split("@")[-1] if "@" in email else ""
        if domain_part:
            e.enrichments["email_domain"] = domain_part
            # Known disposable mail services
            disposable = {
                "guerrillamail",
                "mailinator",
                "tempmail",
                "throwaway",
                "yopmail",
                "sharklasers",
                "grr.la",
                "guerrillamailblock",
            }
            if any(d in domain_part.lower() for d in disposable):
                e.reputation = "suspicious"
                e.tags.append("disposable-email")
        result.enriched.append(e)

    result.total_enriched = len(result.enriched)
    return result
