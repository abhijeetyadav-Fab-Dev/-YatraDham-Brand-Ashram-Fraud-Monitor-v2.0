"""
Enrichment & Forensic Attribution Engine.
Resolves DNS, IP Geolocation, ASN, WHOIS/RDAP registration data,
and SSL Certificate forensic details for detected hosts.
"""
import socket
import ssl
import json
import urllib.request
import urllib.error
import re
from typing import Dict, Any, Optional, Tuple, List
from .models import WhoisData, HostInfo

class ForensicEnricher:
    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout
        self.rdap_cache: Dict[str, Dict[str, Any]] = {}
        self.ip_cache: Dict[str, Dict[str, Any]] = {}

    def resolve_ip(self, host: str) -> Tuple[Optional[str], List[str]]:
        """Resolves host to primary IPv4 and all associated IPs."""
        try:
            # Strip scheme or path if present
            clean_host = host.split('/')[0].split(':')[0].strip()
            _, _, ip_list = socket.gethostbyname_ex(clean_host)
            return (ip_list[0] if ip_list else None, ip_list)
        except (socket.gaierror, socket.herror, IndexError, Exception):
            return (None, [])

    def get_ip_host_info(self, ip: Optional[str]) -> HostInfo:
        """Enriches an IP address with Hosting Provider, ASN, and Geolocation via RDAP/IP-API."""
        if not ip:
            return HostInfo()
        
        if ip in self.ip_cache:
            data = self.ip_cache[ip]
            return HostInfo(
                ip=ip,
                hosting_provider=data.get("hosting_provider", "Unknown"),
                asn=data.get("asn", ""),
                host_country=data.get("host_country", "Unknown"),
                host_city=data.get("host_city", ""),
                reverse_dns=data.get("reverse_dns", "")
            )

        host_info = HostInfo(ip=ip)
        # Try reverse DNS
        try:
            rev_name, _, _ = socket.gethostbyaddr(ip)
            host_info.reverse_dns = rev_name
        except Exception:
            pass

        # Query ip-api
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,org,as,query"
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "YatraDham-Fraud-Monitor/2.0"}
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                if data.get("status") == "success":
                    host_info.hosting_provider = data.get("isp") or data.get("org") or "Unknown"
                    host_info.asn = data.get("as", "")
                    host_info.host_country = data.get("country", "Unknown")
                    host_info.host_city = data.get("city", "")
                    self.ip_cache[ip] = {
                        "hosting_provider": host_info.hosting_provider,
                        "asn": host_info.asn,
                        "host_country": host_info.host_country,
                        "host_city": host_info.host_city,
                        "reverse_dns": host_info.reverse_dns
                    }
                    return host_info
        except Exception:
            pass

        # Fallback provider detection from reverse DNS
        rev = host_info.reverse_dns.lower()
        if "cloudflare" in rev:
            host_info.hosting_provider = "Cloudflare, Inc."
        elif "unifiedlayer" in rev or "hostgator" in rev or "bluehost" in rev:
            host_info.hosting_provider = "Unified Layer (Newfold Digital)"
        elif "hostinger" in rev:
            host_info.hosting_provider = "Hostinger International Ltd"
        elif "godaddy" in rev:
            host_info.hosting_provider = "GoDaddy.com, LLC"
        elif "amazonaws" in rev or "aws" in rev:
            host_info.hosting_provider = "Amazon.com, Inc. (AWS)"
        elif "google" in rev:
            host_info.hosting_provider = "Google LLC"
        elif "hetzner" in rev:
            host_info.hosting_provider = "Hetzner Online GmbH"

        return host_info

    def get_rdap_whois(self, domain: str) -> WhoisData:
        """Queries ICANN / Registry RDAP for domain registration details."""
        clean_dom = domain.split('/')[0].split(':')[0].strip().lower()
        # Handle subdomains to get registrable root
        parts = clean_dom.split('.')
        if len(parts) > 2 and parts[-2] in ('co', 'org', 'net', 'gov', 'edu', 'com'):
            root_dom = '.'.join(parts[-3:])
        elif len(parts) > 2:
            root_dom = '.'.join(parts[-2:])
        else:
            root_dom = clean_dom

        if root_dom in self.rdap_cache:
            cached = self.rdap_cache[root_dom]
            return WhoisData(**cached)

        whois_data = WhoisData()
        url = f"https://rdap.org/domain/{root_dom}"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "YatraDham-Fraud-Monitor/2.0", "Accept": "application/rdap+json, application/json"}
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                whois_data.raw_rdap = data
                
                # Parse events (created, updated, expiration)
                for event in data.get("events", []):
                    action = event.get("eventAction", "")
                    date = event.get("eventDate", "")
                    if action == "registration":
                        whois_data.created = date
                    elif action == "last changed":
                        whois_data.updated = date
                    elif action == "expiration":
                        whois_data.expires = date

                # Parse status
                whois_data.status = data.get("status", [])

                # Parse nameservers
                ns_list = []
                for ns in data.get("nameservers", []):
                    ldh = ns.get("ldhName", "")
                    if ldh:
                        ns_list.append(ldh)
                whois_data.nameservers = ns_list

                # Parse entities for registrar and abuse email
                for entity in data.get("entities", []):
                    roles = entity.get("roles", [])
                    vcard = entity.get("vcardArray", [])
                    
                    if "registrar" in roles:
                        # Extract registrar name
                        if len(vcard) > 1:
                            for item in vcard[1]:
                                if item[0] == "fn":
                                    whois_data.registrar = item[3]
                        if not whois_data.registrar and "publicIds" in entity:
                            whois_data.registrar = entity["publicIds"][0].get("identifier", "")

                    if "abuse" in roles:
                        if len(vcard) > 1:
                            for item in vcard[1]:
                                if item[0] == "email":
                                    whois_data.abuse_email = item[3]

                    # Check sub-entities for abuse
                    for sub in entity.get("entities", []):
                        if "abuse" in sub.get("roles", []):
                            sub_vcard = sub.get("vcardArray", [])
                            if len(sub_vcard) > 1:
                                for item in sub_vcard[1]:
                                    if item[0] == "email":
                                        whois_data.abuse_email = item[3]

                # Privacy detection
                raw_str = json.dumps(data).lower()
                if any(k in raw_str for k in ["privacy", "proxy", "redacted for privacy", "withheld", "whoisguard"]):
                    whois_data.privacy_protected = True

                self.rdap_cache[root_dom] = {
                    "registrar": whois_data.registrar,
                    "created": whois_data.created,
                    "updated": whois_data.updated,
                    "expires": whois_data.expires,
                    "nameservers": whois_data.nameservers,
                    "status": whois_data.status,
                    "registrant_country": whois_data.registrant_country,
                    "abuse_email": whois_data.abuse_email,
                    "privacy_protected": whois_data.privacy_protected
                }
        except Exception:
            pass

        return whois_data

    def inspect_ssl_cert(self, host: str, port: int = 443) -> Dict[str, Any]:
        """Inspects live TLS/SSL certificate of host."""
        clean_host = host.split('/')[0].split(':')[0].strip()
        cert_info = {"has_ssl": False, "issuer": "", "expires": "", "san": []}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((clean_host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if cert:
                        cert_info["has_ssl"] = True
                        cert_info["expires"] = cert.get("notAfter", "")
                        issuer_parts = []
                        for item in cert.get("issuer", []):
                            for k, v in item:
                                if k == "organizationName":
                                    issuer_parts.append(v)
                        cert_info["issuer"] = ", ".join(issuer_parts)
                        san_list = []
                        for item in cert.get("subjectAltName", []):
                            if item[0] == "DNS":
                                san_list.append(item[1])
                        cert_info["san"] = san_list
        except Exception:
            pass
        return cert_info
