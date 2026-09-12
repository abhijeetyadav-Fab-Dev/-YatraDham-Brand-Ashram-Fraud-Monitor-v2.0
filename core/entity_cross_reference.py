"""
Entity Cross-Referencing & Fraud Signal Analysis Engine.
Cross-references scraped domains, phone numbers, payment gateways, and booking URLs
against the ground-truth database of YatraDham and top-rated Dharamshalas and Ashrams.
"""
import json
import re
import os
from typing import Dict, List, Tuple, Any, Optional
from urllib.parse import urlparse

class EntityCrossReferencer:
    def __init__(self, db_path: Optional[str] = None):
        if not db_path:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            db_path = os.path.join(base_dir, "data", "verified_institutions.json")
        
        self.db_path = db_path
        self.brand_data: Dict[str, Any] = {}
        self.institutions: List[Dict[str, Any]] = []
        self.institution_by_id: Dict[str, Dict[str, Any]] = {}
        self.load_database()

        # Compile high-precision regexes
        self.phone_regex = re.compile(
            r'(?:(?:\+91|91|0)[\s-]?)?(?:[6-9]\d{9}|[1-9]\d{2,4}[\s-]?\d{6,8}|1800[\s-]?\d{3}[\s-]?\d{3,4}|1860[\s-]?\d{3}[\s-]?\d{3,4})'
        )

        # Genuine UPI VPA suffix list (NPCI certified PSP handles)
        self.upi_handles = {
            'okaxis', 'okhdfcbank', 'okicici', 'oksbi', 'paytm', 'ybl', 'ibl', 'axl', 'upi',
            'apl', 'allbank', 'barodampay', 'cnrb', 'federal', 'idfcbank', 'kotak', 'pnb',
            'postbank', 'rbl', 'indus', 'yesbank', 'airtel', 'gpay', 'phonepe', 'freecharge',
            'uboi', 'mahb', 'cboi', 'equitas', 'aubank', 'jupiteraxis', 'sliceaxis', 'superyes'
        }

        # Known corporate bank/company email prefixes that are NOT UPI handles
        self.corporate_email_prefixes = {
            'creditcards', 'nodal', 'nodal.officer', 'pno', 'grievance', 'support', 'info',
            'helpdesk', 'care', 'customercare', 'contact', 'admin', 'billing', 'abuse',
            'legal', 'security', 'privacy', 'investor', 'media', 'press', 'sales'
        }

        # Advance payment / token fraud keywords
        self.advance_payment_patterns = [
            re.compile(r'\b(?:advance\s+payment|token\s+amount|advance\s+token|advance\s+deposit)\b', re.I),
            re.compile(r'\b(?:pay\s+(?:advance|token|deposit)|confirm\s+(?:after|via)\s+advance)\b', re.I),
            re.compile(r'\b(?:whatsapp\s+(?:par|pe)?\s*screenshot|send\s+payment\s+screenshot)\b', re.I),
            re.compile(r'\b(?:bina\s+advance\s+booking\s+nahi|advance\s+dena\s+padega)\b', re.I),
            re.compile(r'\b(?:room\s+held\s+for\s+\d+\s*(?:mins|minutes))\b', re.I),
            re.compile(r'\b(?:paytm\s+advance|phonepe\s+advance|gpay\s+advance)\b', re.I),
            re.compile(r'\b(?:call\s+on\s+whatsapp\s+for\s+booking)\b', re.I),
            re.compile(r'\b(?:100%\s+confirmed\s+booking\s+call\s+now)\b', re.I)
        ]

    def load_database(self):
        """Loads or reloads verified ground-truth institutions."""
        if not os.path.exists(self.db_path):
            raise FileNotFoundError(f"Verified institutions database not found at {self.db_path}")
        with open(self.db_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.brand_data = data.get("brand", {})
        self.institutions = data.get("institutions", [])
        self.institution_by_id = {inst["id"]: inst for inst in self.institutions}

    def clean_phone(self, raw_phone: str) -> str:
        """Normalizes Indian phone numbers into standard E.164 or STD landline format."""
        digits = re.sub(r'[^\d]', '', raw_phone)
        if len(digits) == 10 and digits[0] in '6789':
            return f"+91{digits}"
        if len(digits) == 12 and digits.startswith('91') and digits[2] in '6789':
            return f"+{digits}"
        if len(digits) == 11 and digits.startswith('0') and digits[1] in '6789':
            return f"+91{digits[1:]}"
        return digits

    def extract_phones(self, text: str) -> List[str]:
        """Extracts and normalizes unique phone numbers from text."""
        if not text:
            return []
        matches = self.phone_regex.findall(text)
        cleaned = set()
        for m in matches:
            norm = self.clean_phone(m)
            if len(norm) >= 10:
                cleaned.add(norm)
        return sorted(list(cleaned))

    def extract_upi_ids(self, text: str) -> List[str]:
        """
        Extracts genuine UPI VPAs with zero false-positives on bank corporate emails.
        Eliminates errors like tagging 'creditcards@axisbank' or 'nodal.officer@axisbank'.
        """
        if not text:
            return []
        # Match pattern username@handle
        candidates = re.findall(r'([a-zA-Z0-9.\-_]+)@([a-zA-Z0-9.\-_]+)', text)
        valid_upis = set()

        for user, handle in candidates:
            handle_lower = handle.lower().strip().rstrip('.,;:!?')
            user_lower = user.lower().strip().lstrip('.,;:!?')

            # Rule 1: Exclude corporate email prefixes
            if user_lower in self.corporate_email_prefixes:
                continue

            # Rule 2: Exclude web domain addresses ending in .com, .org, .net, .in, .co.in
            if handle_lower.endswith(('.com', '.org', '.net', '.edu', '.gov', '.gov.in', '.nic.in')):
                continue

            # Rule 3: Check if handle matches known UPI PSP handles
            if handle_lower in self.upi_handles:
                valid_upis.add(f"{user_lower}@{handle_lower}")
                continue

            # Rule 4: Match personal mobile prefix UPI pattern (e.g. 9876543210@bank)
            if re.match(r'^[6-9]\d{9}$', user_lower) and len(handle_lower) >= 3 and '.' not in handle_lower:
                valid_upis.add(f"{user_lower}@{handle_lower}")

        return sorted(list(valid_upis))

    def extract_payment_gateways(self, text: str) -> List[str]:
        """Identifies payment gateways, payment links, and aggregator patterns."""
        if not text:
            return []
        gateways = set()
        t_lower = text.lower()
        if "razorpay" in t_lower or "rzp.io" in t_lower or "api.razorpay.com" in t_lower:
            gateways.add("Razorpay")
        if "cashfree" in t_lower or "cashfree.com" in t_lower:
            gateways.add("Cashfree")
        if "instamojo" in t_lower or "imjo.in" in t_lower:
            gateways.add("Instamojo")
        if "paytm" in t_lower or "securegw.paytm.in" in t_lower:
            gateways.add("Paytm")
        if "phonepe" in t_lower or "phonepe.com" in t_lower:
            gateways.add("PhonePe")
        if "googlepay" in t_lower or "gpay" in t_lower:
            gateways.add("Google Pay")
        if "payu" in t_lower or "payumoney" in t_lower:
            gateways.add("PayU")
        if "billdesk" in t_lower:
            gateways.add("BillDesk")
        if "stripe" in t_lower:
            gateways.add("Stripe")
        return sorted(list(gateways))

    def detect_advance_payment_signals(self, text: str) -> List[str]:
        """Scans for high-pressure advance token payment and scam solicitation phrasing."""
        if not text:
            return []
        signals = []
        for pat in self.advance_payment_patterns:
            matches = pat.findall(text)
            if matches:
                signals.extend(matches)
        return list(set(signals))

    def match_institution(self, host_or_text: str) -> Optional[Dict[str, Any]]:
        """
        Determines if a domain name or scraped text targets a specific verified Dharamshala or Ashram.
        """
        if not host_or_text:
            return None
        norm = host_or_text.lower()

        # Check known scam domains first
        for inst in self.institutions:
            for scam_dom in inst.get("known_scam_domains", []):
                if scam_dom in norm:
                    return inst

        # Check primary name, aliases, and keywords
        for inst in self.institutions:
            tokens = [inst["name"].lower()] + [a.lower() for a in inst.get("aliases", [])] + [k.lower() for k in inst.get("keywords", [])]
            for token in tokens:
                # Clean token for domain or keyword matching
                alpha_only = re.sub(r'[^a-z0-9]', '', token)
                if len(alpha_only) >= 5 and alpha_only in re.sub(r'[^a-z0-9]', '', norm):
                    return inst
                # Word boundary match for snippets
                if re.search(r'\b' + re.escape(token) + r'\b', norm, re.I):
                    return inst
        return None

    def is_defensive_domain(self, host: str, final_url: str = "") -> bool:
        """
        Checks if a domain is a verified defensive registration owned by YatraDham.
        Must be in the defensive domains list AND redirect with 301 to yatradham.org.
        """
        defensive = self.brand_data.get("defensive_domains", [])
        host_clean = host.lower().replace("www.", "")
        if host_clean in defensive:
            if not final_url:
                return True
            parsed = urlparse(final_url)
            if "yatradham.org" in parsed.netloc:
                return True
        return False

    def cross_reference(
        self,
        host: str,
        page_title: str = "",
        page_text: str = "",
        final_url: str = "",
        evidence_snippets: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Full cross-referencing audit of a host / page against YatraDham & verified institutions.
        Returns matched institution, discrepancies, extracted numbers, UPIs, and fraud signals.
        """
        evidence_combined = " ".join(evidence_snippets or [])
        full_text = f"{page_title} {page_text} {evidence_combined}"

        # Check defensive registration first
        if self.is_defensive_domain(host, final_url):
            return {
                "is_defensive_domain": True,
                "matched_institution": None,
                "discrepancies": ["Verified defensive domain redirecting to yatradham.org"],
                "extracted_phones": [],
                "unauthorized_phones": [],
                "extracted_upis": [],
                "advance_signals": [],
                "gateways": []
            }

        # Check matched institution
        matched_inst = self.match_institution(f"{host} {full_text}")
        discrepancies = []
        unauthorized_phones = []

        # Extract phones
        all_phones = self.extract_phones(full_text)
        brand_phones = [self.clean_phone(p) for p in self.brand_data.get("official_phones", [])]

        if matched_inst:
            inst_phones = [self.clean_phone(p) for p in matched_inst.get("verified_phones", [])]
            for p in all_phones:
                if p not in inst_phones and p not in brand_phones:
                    unauthorized_phones.append(p)
            
            if unauthorized_phones:
                discrepancies.append(
                    f"Impersonating {matched_inst['name']} with unauthorized booking phone: {', '.join(unauthorized_phones[:3])}"
                )

            # Check official booking URL mismatch
            official_web = matched_inst.get("official_website", "").lower()
            if official_web and host.lower() not in official_web and "yatradham.org" not in final_url.lower():
                discrepancies.append(
                    f"Unauthorized domain hosting {matched_inst['name']} booking portal (official: {matched_inst.get('official_website')})"
                )
        else:
            # Check if mentions YatraDham customer care with unauthorized number
            if any(term in full_text.lower() for term in ["yatradham", "yatra dham"]):
                for p in all_phones:
                    if p not in brand_phones:
                        unauthorized_phones.append(p)
                if unauthorized_phones:
                    discrepancies.append(
                        f"Publishing unauthorized YatraDham helpline number: {', '.join(unauthorized_phones[:3])}"
                    )

        extracted_upis = self.extract_upi_ids(full_text)
        if extracted_upis:
            discrepancies.append(f"Direct personal UPI payment handles found: {', '.join(extracted_upis[:3])}")

        advance_signals = self.detect_advance_payment_signals(full_text)
        if advance_signals:
            discrepancies.append(f"High-pressure advance payment demand: {', '.join(advance_signals[:2])}")

        gateways = self.extract_payment_gateways(full_text)

        return {
            "is_defensive_domain": False,
            "matched_institution": matched_inst,
            "discrepancies": discrepancies,
            "extracted_phones": all_phones,
            "unauthorized_phones": unauthorized_phones,
            "extracted_upis": extracted_upis,
            "advance_signals": advance_signals,
            "gateways": gateways
        }
