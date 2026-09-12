"""
Data models and schema definitions for YatraDham Brand & Ashram Fraud Monitor.
"""
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
import datetime

class ThreatCategory(str, Enum):
    BRAND_TYPOSQUAT = "BRAND_TYPOSQUAT"
    ASHRAM_IMPERSONATION = "ASHRAM_IMPERSONATION"
    FAKE_HELPLINE = "FAKE_HELPLINE"
    SUSPICIOUS_PAYMENT_UPI = "SUSPICIOUS_PAYMENT_UPI"
    SOCIAL_PROFILE_PHISHING = "SOCIAL_PROFILE_PHISHING"
    DEFENSIVE_OWNED = "DEFENSIVE_OWNED"

class RiskBand(str, Enum):
    CRITICAL = "CRITICAL"      # 75 - 100: Active phishing / unauthorized payment / fake helpline
    HIGH = "HIGH"              # 55 - 74: Suspicious lookalike / mismatched contact / new unverified
    MEDIUM = "MEDIUM"          # 35 - 54: Low-trust aggregator / UGC helpline mention / suspicious name
    LOW = "LOW"                # 1 - 34: General mentions / low relevance
    BRAND_OWNED = "BRAND-OWNED"# 0: Verified legitimate defensive registration (301 to yatradham.org)

class CaseStatus(str, Enum):
    NEW = "NEW"
    UNDER_REVIEW = "UNDER_REVIEW"
    TAKEDOWN_SENT = "TAKEDOWN_SENT"
    BLOCKED = "BLOCKED"
    RESOLVED = "RESOLVED"
    WHITELISTED = "WHITELISTED"

@dataclass
class EvidenceItem:
    url: str
    title: str = ""
    query: str = ""
    snippet: str = ""
    timestamp: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

@dataclass
class PageInspection:
    reachable: bool = False
    status_code: Optional[int] = None
    title: str = ""
    final_url: str = ""
    redirects_to_official: bool = False
    copied_phones: List[str] = field(default_factory=list)
    copied_emails: List[str] = field(default_factory=list)
    upi_ids: List[str] = field(default_factory=list)
    payment_signals: List[str] = field(default_factory=list)
    gateways: List[str] = field(default_factory=list)
    advance_payment_signals: List[str] = field(default_factory=list)
    brand_mentions: int = 0
    matched_institution_id: Optional[str] = None
    matched_institution_name: Optional[str] = None
    discrepancies: List[str] = field(default_factory=list)

@dataclass
class WhoisData:
    registrar: str = ""
    created: str = ""
    updated: str = ""
    expires: str = ""
    nameservers: List[str] = field(default_factory=list)
    status: List[str] = field(default_factory=list)
    registrant_country: Optional[str] = None
    abuse_email: str = ""
    privacy_protected: bool = False
    raw_rdap: Dict[str, Any] = field(default_factory=dict)

@dataclass
class HostInfo:
    ip: str = ""
    hosting_provider: str = ""
    asn: str = ""
    host_country: str = ""
    host_city: str = ""
    reverse_dns: str = ""

@dataclass
class TakedownDossier:
    ncrp_category: str = "Online Financial Fraud / Fake Website / Phishing"
    ncrp_sub_category: str = "Cheating by Impersonation (Fake Temple / Dharamshala Booking)"
    legal_statutes: List[str] = field(default_factory=lambda: [
        "IT Act 2000 Section 66C (Identity Theft)",
        "IT Act 2000 Section 66D (Cheating by Personation using Computer Resource)",
        "Bharatiya Nyaya Sanhita 2023 Sec 318(4) / 319 (Cheating & Dishonestly Inducing Delivery of Property / Personation)",
        "IPC Section 419 / 420"
    ])
    complaint_subject: str = ""
    police_memo: str = ""
    registrar_abuse_notice: str = ""
    nixi_notice: str = ""
    npci_bank_freeze_request: str = ""
    chakshu_dot_report: str = ""
    google_safebrowsing_url: str = ""
    target_summary: str = ""

@dataclass
class FraudFinding:
    host: str
    registrable_domain: str
    threat_category: ThreatCategory
    risk_score: int
    risk_band: RiskBand
    risk_reasons: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    evidence: List[EvidenceItem] = field(default_factory=list)
    ip: str = ""
    host_info: HostInfo = field(default_factory=HostInfo)
    whois: WhoisData = field(default_factory=WhoisData)
    page: PageInspection = field(default_factory=PageInspection)
    takedown: TakedownDossier = field(default_factory=TakedownDossier)
    targeted_institution_id: Optional[str] = None
    targeted_institution_name: Optional[str] = None
    case_status: CaseStatus = CaseStatus.NEW
    case_notes: List[Dict[str, Any]] = field(default_factory=list)
    fir_number: Optional[str] = None
    syndicate_id: Optional[str] = None
    first_detected: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    is_new: bool = True

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["threat_category"] = self.threat_category.value
        d["risk_band"] = self.risk_band.value
        d["case_status"] = self.case_status.value
        return d
