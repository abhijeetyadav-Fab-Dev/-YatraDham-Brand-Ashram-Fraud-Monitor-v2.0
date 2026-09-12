"""
Multi-Channel Detection Engine for YatraDham Brand & Ashram Fraud Monitor.
Coordinates Permutation DNS, Certificate Transparency (crt.sh),
Open-Web Search Scraping, Social Media Surveillance, and Deep Page Inspection.
"""
import concurrent.futures
import json
import re
import socket
import urllib.request
import urllib.parse
import urllib.error
from typing import Dict, List, Set, Any, Optional, Tuple
from bs4 import BeautifulSoup
from .models import ThreatCategory, EvidenceItem, PageInspection
from .entity_cross_reference import EntityCrossReferencer

class DetectionEngine:
    def __init__(self, cross_referencer: Optional[EntityCrossReferencer] = None, max_workers: int = 25, timeout: float = 5.0):
        self.ecr = cross_referencer or EntityCrossReferencer()
        self.max_workers = max_workers
        self.timeout = timeout

        # Typosquat brand permutations
        self.brand_tokens = ["yatradham", "yatra-dham", "yatradhams", "yathradham", "yatradam"]
        self.intent_tokens = ["", "-booking", "-online", "-trust", "-helpline", "-care", "-refund", "-support", "-pay", "-stay"]
        self.tlds = [".com", ".in", ".org", ".co.in", ".online", ".site", ".live", ".net", ".info"]

    def generate_permutations(self) -> List[str]:
        """Generates permutation domains for brand AND top high-risk ashrams."""
        candidates = set()
        
        # 1. Brand permutations
        for b in self.brand_tokens:
            for i in self.intent_tokens:
                for t in self.tlds:
                    candidates.add(f"{b}{i}{t}")

        # 2. Ashram & Dharamshala targeted permutations
        ashram_roots = [
            "salasarbalaji", "khatushyam", "bhujvishranti", "kedarnathdharamshala",
            "badrinathdharamshala", "ujjainmahakal", "shirdisaibhaktnivas",
            "tirupatidharamshala", "ayodhyaramdham", "somnathbooking",
            "panchaldharamshala", "gujaratidharamshala"
        ]
        ashram_intents = ["", "booking", "online", "room", "advance"]
        ashram_tlds = [".in", ".com", ".org", ".co.in", ".online"]

        for root in ashram_roots:
            for intent in ashram_intents:
                connector = "-" if intent else ""
                name = f"{root}{connector}{intent}"
                for t in ashram_tlds:
                    candidates.add(f"{name}{t}")

        return sorted(list(candidates))

    def resolve_domain(self, domain: str) -> Optional[Tuple[str, str]]:
        """Resolves domain to IP; returns (domain, ip) if live, else None."""
        try:
            clean_dom = domain.split('/')[0].split(':')[0].strip()
            ip = socket.gethostbyname(clean_dom)
            return (domain, ip)
        except Exception:
            return None

    def run_permutation_sweep(self, candidates: Optional[List[str]] = None) -> Dict[str, str]:
        """Resolves domain list concurrently; returns {domain: ip} for all live hosts."""
        domains = candidates or self.generate_permutations()
        live_hosts = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.resolve_domain, d): d for d in domains}
            for fut in concurrent.futures.as_completed(futures):
                res = fut.result()
                if res:
                    dom, ip = res
                    live_hosts[dom] = ip
        return live_hosts

    def query_certificate_transparency(self, query: str = "%yatradham%") -> List[str]:
        """Queries crt.sh for recent TLS certificate issuances matching wildcard."""
        url = f"https://crt.sh/?q={urllib.parse.quote(query)}&output=json"
        domains = set()
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) YatraDham-Fraud-Monitor/2.0"}
            )
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                for entry in data:
                    name = entry.get("name_value", "")
                    for d in name.split("\n"):
                        d_clean = d.replace("*.", "").strip().lower()
                        if d_clean and "." in d_clean:
                            domains.add(d_clean)
        except Exception:
            pass
        return sorted(list(domains))

    def scrape_search_results(self, queries: Optional[List[str]] = None) -> List[EvidenceItem]:
        """
        Scrapes open web search engine results for high-risk queries.
        Extracts titles, snippets, and destination landing URLs.
        """
        search_queries = queries or [
            "yatradham customer care number",
            "yatradham booking helpline number",
            "yatradham refund number",
            "bhuj vishranti bhavan booking contact number",
            "salasar balaji dharamshala advance booking number",
            "khatu shyam dharamshala room booking number",
            "kedarnath gmvn cottage advance booking paytm",
            "ujjain mahakaleshwar dharamshala booking number",
            "panchal dharamshala ambaji booking"
        ]

        evidence_items = []

        for q in search_queries:
            try:
                # DuckDuckGo HTML endpoint
                search_url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(q)}"
                req = urllib.request.Request(
                    search_url,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0"
                    }
                )
                with urllib.request.urlopen(req, timeout=8.0) as resp:
                    soup = BeautifulSoup(resp.read(), "html.parser")
                    results = soup.find_all("div", class_="result")
                    for r in results[:6]: # top 6 results per query
                        title_tag = r.find("a", class_="result__a")
                        snippet_tag = r.find("a", class_="result__snippet")
                        url_tag = r.find("a", class_="result__url")
                        
                        if title_tag:
                            title = title_tag.get_text(strip=True)
                            raw_href = title_tag.get("href", "")
                            # Parse unredirect URL if DDG uddg param exists
                            dest_url = raw_href
                            if "uddg=" in raw_href:
                                parsed = urllib.parse.parse_qs(urllib.parse.urlparse(raw_href).query)
                                if "uddg" in parsed:
                                    dest_url = parsed["uddg"][0]

                            snippet = snippet_tag.get_text(strip=True) if snippet_tag else ""
                            evidence_items.append(EvidenceItem(
                                url=dest_url,
                                title=title,
                                query=q,
                                snippet=snippet
                            ))
            except Exception:
                continue

        return evidence_items

    def inspect_page(self, url: str) -> PageInspection:
        """
        Deep crawler that inspects the page HTTP response, redirects, content,
        contacts, payment gateways, and UPI identifiers.
        """
        if not url.startswith("http"):
            url = f"https://{url}"

        inspection = PageInspection(final_url=url)
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                }
            )
            # Custom opener to follow redirects and record final URL
            opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler)
            with opener.open(req, timeout=self.timeout) as resp:
                inspection.reachable = True
                inspection.status_code = resp.getcode()
                inspection.final_url = resp.geturl()
                
                # Check redirect to official site
                final_parsed = urllib.parse.urlparse(inspection.final_url)
                if "yatradham.org" in final_parsed.netloc:
                    inspection.redirects_to_official = True

                html = resp.read().decode('utf-8', errors='ignore')
                soup = BeautifulSoup(html, "html.parser")

                inspection.title = soup.title.get_text(strip=True) if soup.title else ""
                body_text = soup.get_text(separator=" ", strip=True)

                # Extract brand mentions
                inspection.brand_mentions = len(re.findall(r'yatradham|yatra\s*dham', body_text, re.I))

                # Extract tracking tags for syndicate clustering
                gtm_matches = list(set(re.findall(r'GTM-[A-Z0-9]{4,10}', html)))
                ga_matches = list(set(re.findall(r'(?:UA-\d+-\d+|G-[A-Z0-9]{6,12})', html)))
                inspection.gtm_ids = gtm_matches
                inspection.ga_ids = ga_matches

                # Extract deep UPI links and QR code indicators
                upi_deep_links = re.findall(r'upi://pay\?[^\s"\'<>]+', html, re.I)
                for ulink in upi_deep_links:
                    inspection.qr_payment_links.append(ulink)
                    pa_match = re.search(r'pa=([a-zA-Z0-9.\-_]+@[a-zA-Z0-9.\-_]+)', ulink)
                    if pa_match:
                        vpa = pa_match.group(1).lower()
                        if vpa not in inspection.upi_ids:
                            inspection.upi_ids.append(vpa)

                # Check for QR code images
                qr_imgs = soup.find_all("img", src=re.compile(r'qr|scan|upi', re.I))
                if qr_imgs or upi_deep_links:
                    inspection.advance_payment_signals.append("Embedded QR code / UPI deep link for advance payment")

                # Check WhatsApp redirect
                if "wa.me" in html or "api.whatsapp.com" in html:
                    inspection.advance_payment_signals.append("WhatsApp direct booking link (wa.me)")

                # Cross-reference with ground truth
                host = urllib.parse.urlparse(url).netloc
                xref = self.ecr.cross_reference(
                    host=host,
                    page_title=inspection.title,
                    page_text=body_text[:5000],
                    final_url=inspection.final_url
                )

                if xref.get("matched_institution"):
                    inst = xref["matched_institution"]
                    inspection.matched_institution_id = inst.get("id")
                    inspection.matched_institution_name = inst.get("name")

                inspection.copied_phones = xref.get("unauthorized_phones", [])
                for u in xref.get("extracted_upis", []):
                    if u not in inspection.upi_ids:
                        inspection.upi_ids.append(u)
                inspection.gateways = xref.get("gateways", [])
                inspection.advance_payment_signals.extend(xref.get("advance_signals", []))
                inspection.discrepancies = xref.get("discrepancies", [])

        except urllib.error.HTTPError as e:
            inspection.reachable = True
            inspection.status_code = e.code
        except Exception:
            inspection.reachable = False

        return inspection
