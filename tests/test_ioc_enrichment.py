"""Tests for HashGuard IOC enrichment module."""

import socket
from unittest.mock import MagicMock, patch

import pytest

from hashguard.ioc_enrichment import (
    EnrichedIOC,
    EnrichmentResult,
    _resolve_dns,
    _reverse_dns,
    _query_ip_api,
    _query_abuseipdb,
    _query_urlhaus_host,
    enrich_ip,
    enrich_domain,
    enrich_url,
    enrich_iocs,
)

# ── Dataclasses ──────────────────────────────────────────────────────────────


class TestEnrichedIOC:
    def test_defaults(self):
        e = EnrichedIOC(value="1.2.3.4", ioc_type="ip")
        assert e.reputation == "unknown"
        assert e.tags == []
        assert e.enrichments == {}


class TestEnrichmentResult:
    def test_defaults(self):
        r = EnrichmentResult()
        assert r.enriched == []
        assert r.total_enriched == 0

    def test_to_dict(self):
        e = EnrichedIOC(value="1.2.3.4", ioc_type="ip", reputation="malicious", tags=["bad"])
        r = EnrichmentResult(enriched=[e], total_enriched=1)
        d = r.to_dict()
        assert d["total_enriched"] == 1
        assert d["enriched"][0]["value"] == "1.2.3.4"
        assert d["enriched"][0]["reputation"] == "malicious"


# ── DNS lookups ──────────────────────────────────────────────────────────────


class TestResolveDNS:
    @patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))],
    )
    def test_resolve_success(self, mock_gai):
        result = _resolve_dns("example.com")
        assert "resolved_ips" in result
        assert "93.184.216.34" in result["resolved_ips"]

    @patch("socket.getaddrinfo", side_effect=socket.gaierror)
    def test_resolve_nxdomain(self, mock_gai):
        result = _resolve_dns("nonexistent.invalid")
        assert result.get("dns_status") == "NXDOMAIN"


class TestReverseDNS:
    @patch("socket.gethostbyaddr", return_value=("ns1.example.com", [], []))
    def test_success(self, mock_rev):
        result = _reverse_dns("93.184.216.34")
        assert result["reverse_dns"] == "ns1.example.com"

    @patch("socket.gethostbyaddr", side_effect=socket.herror)
    def test_failure(self, mock_rev):
        result = _reverse_dns("1.2.3.4")
        assert result["reverse_dns"] == "none"


# ── Per-IOC enrichment ───────────────────────────────────────────────────────


class TestEnrichIP:
    @patch("hashguard.ioc_enrichment._query_urlhaus_host", return_value={})
    @patch("hashguard.ioc_enrichment._query_ip_api", return_value={"country": "US"})
    @patch(
        "hashguard.ioc_enrichment._reverse_dns", return_value={"reverse_dns": "host.example.com"}
    )
    def test_enriches_ip(self, mock_rdns, mock_geoip, mock_urlhaus):
        result = enrich_ip("8.8.8.8")
        assert result.ioc_type == "ip"
        assert result.enrichments["country"] == "US"
        assert result.enrichments["reverse_dns"] == "host.example.com"

    @patch("hashguard.ioc_enrichment._query_urlhaus_host", return_value={"urlhaus": "malicious"})
    @patch("hashguard.ioc_enrichment._query_ip_api", return_value={})
    @patch("hashguard.ioc_enrichment._reverse_dns", return_value={})
    def test_malicious_urlhaus(self, mock_rdns, mock_geoip, mock_urlhaus):
        result = enrich_ip("1.2.3.4")
        assert result.reputation == "malicious"
        assert "urlhaus-listed" in result.tags


class TestEnrichDomain:
    @patch("hashguard.ioc_enrichment._query_urlhaus_host", return_value={})
    @patch("hashguard.ioc_enrichment._whois_lookup", return_value={"registrar": "TestReg"})
    @patch("hashguard.ioc_enrichment._resolve_dns", return_value={"resolved_ips": "1.2.3.4"})
    def test_enriches_domain(self, mock_dns, mock_whois, mock_urlhaus):
        result = enrich_domain("example.com")
        assert result.ioc_type == "domain"
        assert result.enrichments["registrar"] == "TestReg"

    @patch("hashguard.ioc_enrichment._query_urlhaus_host", return_value={})
    @patch("hashguard.ioc_enrichment._whois_lookup", return_value={})
    @patch("hashguard.ioc_enrichment._resolve_dns", return_value={"dns_status": "NXDOMAIN"})
    def test_nxdomain_tag(self, mock_dns, mock_whois, mock_urlhaus):
        result = enrich_domain("nonexistent.invalid")
        assert "nxdomain" in result.tags


class TestEnrichURL:
    @patch("requests.post")
    def test_clean_url(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"query_status": "no_results"}
        mock_post.return_value = mock_resp
        result = enrich_url("http://clean.example.com/page")
        assert result.enrichments.get("urlhaus") == "clean"

    @patch("requests.post")
    def test_malicious_url(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"query_status": "ok", "threat": "payload_delivery"}
        mock_post.return_value = mock_resp
        result = enrich_url("http://evil.com/payload")
        assert result.reputation == "malicious"
        assert "urlhaus-listed" in result.tags


# ── Batch enrichment ─────────────────────────────────────────────────────────


class TestEnrichIOCs:
    @patch("hashguard.ioc_enrichment.enrich_url")
    @patch("hashguard.ioc_enrichment.enrich_domain")
    @patch("hashguard.ioc_enrichment.enrich_ip")
    def test_enriches_all_types(self, mock_ip, mock_dom, mock_url):
        mock_ip.return_value = EnrichedIOC(value="1.2.3.4", ioc_type="ip")
        mock_dom.return_value = EnrichedIOC(value="evil.com", ioc_type="domain")
        mock_url.return_value = EnrichedIOC(value="http://evil.com", ioc_type="url")

        result = enrich_iocs(
            {
                "ip_addresses": ["1.2.3.4"],
                "domains": ["evil.com"],
                "urls": ["http://evil.com"],
            }
        )
        assert result.total_enriched >= 3

    def test_enriches_crypto_wallets(self):
        result = enrich_iocs(
            {
                "crypto_wallets": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"],
            }
        )
        assert len(result.enriched) == 1
        assert "bitcoin" in result.enriched[0].tags

    def test_enriches_emails(self):
        result = enrich_iocs(
            {
                "emails": ["attacker@yopmail.com"],
            }
        )
        assert len(result.enriched) == 1
        assert "disposable-email" in result.enriched[0].tags
        assert result.enriched[0].reputation == "suspicious"

    def test_empty_input(self):
        result = enrich_iocs({})
        assert result.total_enriched == 0

    def test_max_per_type_limit(self):
        result = enrich_iocs(
            {"crypto_wallets": [f"1addr{i}" for i in range(20)]},
            max_per_type=3,
        )
        assert result.total_enriched == 3


class TestQueryIpApi:
    """Tests for _query_ip_api helper."""

    @patch("hashguard.ioc_enrichment.requests")
    def test_success(self, mock_requests):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "success",
            "country": "US",
            "city": "Mountain View",
            "isp": "Google LLC",
            "org": "Google",
            "as": "AS15169",
        }
        mock_requests.get.return_value = mock_resp
        result = _query_ip_api("8.8.8.8")
        assert result["country"] == "US"
        assert result["isp"] == "Google LLC"

    @patch("hashguard.ioc_enrichment.requests")
    def test_exception(self, mock_requests):
        mock_requests.get.side_effect = Exception("timeout")
        result = _query_ip_api("1.2.3.4")
        assert result == {}


class TestQueryAbuseIPDB:
    """Tests for _query_abuseipdb helper."""

    def test_no_api_key(self):
        assert _query_abuseipdb("1.2.3.4", api_key="") == {}

    @patch("hashguard.ioc_enrichment.requests")
    def test_success(self, mock_requests):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "abuseConfidenceScore": 85,
                "totalReports": 42,
                "lastReportedAt": "2024-01-01",
                "usageType": "Data Center",
            }
        }
        mock_requests.get.return_value = mock_resp
        result = _query_abuseipdb("1.2.3.4", api_key="testkey")
        assert result["abuse_score"] == "85"
        assert result["total_reports"] == "42"


class TestQueryUrlhausHost:
    """Tests for _query_urlhaus_host helper."""

    @patch("hashguard.ioc_enrichment.requests")
    def test_clean(self, mock_requests):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"query_status": "no_results"}
        mock_requests.post.return_value = mock_resp
        result = _query_urlhaus_host("example.com")
        assert result["urlhaus"] == "clean"

    @patch("hashguard.ioc_enrichment.requests")
    def test_malicious(self, mock_requests):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "query_status": "listed",
            "urls_online": 3,
            "urlhaus_reference": "https://urlhaus.abuse.ch/host/evil.com/",
        }
        mock_requests.post.return_value = mock_resp
        result = _query_urlhaus_host("evil.com")
        assert result["urlhaus"] == "malicious"
        assert result["urlhaus_urls_online"] == "3"


class TestEnrichDomainNewlyRegistered:
    """Test newly-registered domain detection."""

    @patch("hashguard.ioc_enrichment._query_urlhaus_host", return_value={})
    @patch("hashguard.ioc_enrichment._whois_lookup", return_value={"domain_age_days": "10"})
    @patch("hashguard.ioc_enrichment._resolve_dns", return_value={"resolved_ips": "1.2.3.4"})
    def test_newly_registered_suspicious(self, mock_dns, mock_whois, mock_uh):
        enriched = enrich_domain("brand-new.com")
        assert enriched.reputation == "suspicious"
        assert "newly-registered" in enriched.tags

    @patch("hashguard.ioc_enrichment._query_urlhaus_host", return_value={"urlhaus": "malicious"})
    @patch("hashguard.ioc_enrichment._whois_lookup", return_value={})
    @patch("hashguard.ioc_enrichment._resolve_dns", return_value={})
    def test_urlhaus_malicious(self, mock_dns, mock_whois, mock_uh):
        enriched = enrich_domain("evil.com")
        assert enriched.reputation == "malicious"


class TestEnrichIPAbuseIPDB:
    """Tests for AbuseIPDB scoring within enrich_ip."""

    @patch("hashguard.ioc_enrichment._query_urlhaus_host", return_value={})
    @patch("hashguard.ioc_enrichment._query_ip_api", return_value={})
    @patch("hashguard.ioc_enrichment._reverse_dns", return_value={})
    @patch("hashguard.ioc_enrichment._query_abuseipdb", return_value={"abuse_score": "85"})
    def test_high_abuse_score_malicious(self, mock_abuse, mock_rdns, mock_geoip, mock_uh):
        result = enrich_ip("1.2.3.4", abuseipdb_key="testkey")
        assert result.reputation == "malicious"

    @patch("hashguard.ioc_enrichment._query_urlhaus_host", return_value={})
    @patch("hashguard.ioc_enrichment._query_ip_api", return_value={})
    @patch("hashguard.ioc_enrichment._reverse_dns", return_value={})
    @patch("hashguard.ioc_enrichment._query_abuseipdb", return_value={"abuse_score": "50"})
    def test_medium_abuse_score_suspicious(self, mock_abuse, mock_rdns, mock_geoip, mock_uh):
        result = enrich_ip("1.2.3.4", abuseipdb_key="testkey")
        assert result.reputation == "suspicious"

    @patch("hashguard.ioc_enrichment._query_urlhaus_host", return_value={})
    @patch("hashguard.ioc_enrichment._query_ip_api", return_value={})
    @patch("hashguard.ioc_enrichment._reverse_dns", return_value={})
    @patch("hashguard.ioc_enrichment._query_abuseipdb", return_value={"abuse_score": "5"})
    def test_low_abuse_score_unknown(self, mock_abuse, mock_rdns, mock_geoip, mock_uh):
        result = enrich_ip("1.2.3.4", abuseipdb_key="testkey")
        assert result.reputation == "unknown"


class TestWhoisLookup:
    """Tests for _whois_lookup helper."""

    @patch("socket.create_connection")
    def test_whois_success(self, mock_conn):
        from hashguard.ioc_enrichment import _whois_lookup
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [
            b"Registrar: TestReg Inc\r\nCreation Date: 2020-01-15\r\nRegistrant Country: US\r\nName Server: ns1.example.com\r\n",
            b""
        ]
        mock_conn.return_value = mock_sock
        result = _whois_lookup("example.com")
        assert result["registrar"] == "TestReg Inc"
        assert result["created"] == "2020-01-15"
        assert "domain_age_days" in result
        assert result["registrant_country"] == "US"
        assert result["name_servers"] == "ns1.example.com"

    @patch("socket.create_connection", side_effect=OSError("connection refused"))
    def test_whois_failure(self, mock_conn):
        from hashguard.ioc_enrichment import _whois_lookup
        result = _whois_lookup("fail.example.com")
        assert result == {}


class TestEnrichUrlNoRequests:
    """Test enrich_url when requests is not available."""

    def test_no_requests(self):
        with patch("hashguard.ioc_enrichment.HAS_REQUESTS", False):
            result = enrich_url("http://example.com")
            assert result.ioc_type == "url"
            assert result.enrichments == {}


class TestEnrichIOCsExtended:
    """Extended enrichment tests for wallet types and emails."""

    def test_ethereum_wallet(self):
        result = enrich_iocs({"crypto_wallets": ["0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"]})
        assert "ethereum" in result.enriched[0].tags

    def test_monero_wallet(self):
        long_addr = "4" * 95
        result = enrich_iocs({"crypto_wallets": [long_addr]})
        assert "monero" in result.enriched[0].tags

    def test_email_normal_domain(self):
        result = enrich_iocs({"emails": ["user@gmail.com"]})
        assert len(result.enriched) == 1
        assert result.enriched[0].enrichments.get("email_domain") == "gmail.com"


class TestQueryUrlhausHostEdge:
    """Edge cases for _query_urlhaus_host."""

    @patch("hashguard.ioc_enrichment.requests")
    def test_listed_offline(self, mock_requests):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"query_status": "listed", "urls_online": 0}
        mock_requests.post.return_value = mock_resp
        result = _query_urlhaus_host("semi-evil.com")
        assert result["urlhaus"] == "listed (offline)"

    def test_no_requests(self):
        with patch("hashguard.ioc_enrichment.HAS_REQUESTS", False):
            result = _query_urlhaus_host("example.com")
            assert result == {}

    @patch("hashguard.ioc_enrichment.requests")
    def test_exception(self, mock_requests):
        mock_requests.post.side_effect = Exception("timeout")
        result = _query_urlhaus_host("error.com")
        assert result == {}


class TestQueryIpApiNoRequests:
    """Test _query_ip_api when requests not available."""

    def test_no_requests(self):
        with patch("hashguard.ioc_enrichment.HAS_REQUESTS", False):
            result = _query_ip_api("1.2.3.4")
            assert result == {}


class TestQueryAbuseIPDBExtended:
    """Extended tests for _query_abuseipdb."""

    def test_no_requests(self):
        with patch("hashguard.ioc_enrichment.HAS_REQUESTS", False):
            result = _query_abuseipdb("1.2.3.4", api_key="testkey")
            assert result == {}

    @patch("hashguard.ioc_enrichment.requests")
    def test_exception_returns_empty(self, mock_requests):
        mock_requests.get.side_effect = Exception("timeout")
        result = _query_abuseipdb("1.2.3.4", api_key="testkey")
        assert result == {}


class TestResolveDNSGenericException:
    """Test _resolve_dns with generic Exception."""

    @patch("socket.getaddrinfo", side_effect=RuntimeError("unexpected"))
    def test_generic_exception(self, mock_gai):
        result = _resolve_dns("error.example.com")
        assert result == {}


class TestReverseDNSGenericException:
    """Test _reverse_dns with generic Exception."""

    @patch("socket.gethostbyaddr", side_effect=RuntimeError("unexpected"))
    def test_generic_exception(self, mock_rev):
        result = _reverse_dns("1.2.3.4")
        assert result == {}

