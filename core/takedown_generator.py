"""
Takedown Dossier & Law Enforcement Packet Generator.
Generates fully compliant filing packets for the National Cyber Crime Reporting Portal (cybercrime.gov.in),
Bhavnagar/Gujarat Cyber Crime Police Cell, ICANN Registrar Abuse desks, NIXI (.IN Registry),
DoT Chakshu Portal (Sanchar Saathi for SIM/IMEI blocking), and NPCI / Bank Mule UPI freeze requests.
"""
from typing import Dict, Any, List
from datetime import datetime, timezone
from urllib.parse import quote_plus
from .models import TakedownDossier, FraudFinding

class TakedownGenerator:
    def __init__(self, brand_name: str = "YatraDham.org"):
        self.brand_name = brand_name

    def generate(self, finding_data: Dict[str, Any]) -> TakedownDossier:
        """
        Builds a comprehensive legal and technical dossier for immediate takedown and prosecution.
        """
        host = finding_data.get("host", "")
        ip = finding_data.get("ip") or (finding_data.get("host_info") or {}).get("ip", "—")
        host_info = finding_data.get("host_info") or {}
        whois = finding_data.get("whois") or {}
        page = finding_data.get("page") or {}
        reasons = finding_data.get("risk_reasons") or []
        score = finding_data.get("risk_score", 0)
        band = finding_data.get("risk_band", "HIGH")
        inst_name = finding_data.get("targeted_institution_name") or "Religious Pilgrims & YatraDham.org"
        target_url = f"https://{host}/" if not host.startswith("http") else host

        now_ist = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        unauth_phones = page.get("copied_phones") or finding_data.get("unauthorized_phones") or []
        upis = page.get("upi_ids") or finding_data.get("extracted_upis") or []
        gateways = page.get("gateways") or []
        advance_signals = page.get("advance_payment_signals") or []

        registrar = whois.get("registrar", "Unknown Registrar")
        abuse_email = whois.get("abuse_email", "")
        hosting_provider = host_info.get("hosting_provider", "Unknown Host")
        asn = host_info.get("asn", "—")
        country = host_info.get("host_country", "—")
        created_date = whois.get("created", "—")

        # 1. Subject line
        subject = f"CYBERCRIME REPORT: Active Impersonation & Online Advance Booking Fraud on {host}"

        # 2. Police / NCRP Narrative
        ncrp_narrative = (
            f"TO: National Cyber Crime Reporting Portal (NCRP) / Gujarat Cyber Crime Cell\n"
            f"COMPLAINT TYPE: Online Financial Fraud / Fake Impersonating Website & Payment Phishing\n"
            f"STATUTORY PROVISIONS: Sections 66C & 66D of Information Technology Act 2000; "
            f"Sections 318(4) & 319 of Bharatiya Nyaya Sanhita (BNS) 2023 (Sec 419/420 IPC)\n\n"
            f"1. INCIDENT BRIEF & COMPLAINANT IDENTIFICATION:\n"
            f"This complaint is formally filed by YatraDham.org (YatraDham E-Services Pvt Ltd, Bhavnagar, Gujarat), "
            f"operating under the Digital Trust & Safety Initiative from YatraDham.Org.\n"
            f"The suspect target '{host}' has been detected actively cheating religious devotees and pilgrims by "
            f"impersonating '{inst_name}'. The perpetrators are dishonestly soliciting unauthorized advance booking deposits "
            f"and payments under the false pretext of confirmed Dharamshala/Ashram room allocations.\n\n"
            f"2. SUSPECT ELECTRONIC & TECHNICAL ATTRIBUTION:\n"
            f"- Suspect Impersonating URL: {target_url}\n"
            f"- Server IP Address: {ip}\n"
            f"- Hosting Provider / ISP: {hosting_provider}\n"
            f"- Autonomous System (ASN): {asn}\n"
            f"- Server Physical Location: {country}\n"
            f"- Domain Registrar: {registrar}\n"
            f"- Domain Registration Date: {created_date}\n\n"
            f"3. SUSPECT FINANCIAL & TELECOM IDENTIFIERS:\n"
            f"- Fraudulent Contact / Helpline Numbers: {', '.join(unauth_phones) if unauth_phones else 'Displayed on landing page/WhatsApp'}\n"
            f"- Suspect UPI Payment Handles (VPAs): {', '.join(upis) if upis else 'QR Code / Direct Bank Transfer'}\n"
            f"- Payment Gateways / Aggregators: {', '.join(gateways) if gateways else 'Direct UPI / QR'}\n"
            f"- High-Pressure Advance Payment Demands: {', '.join(advance_signals) if advance_signals else 'Token advance required'}\n\n"
            f"4. FORENSIC RISK SCORE: {score}/100 ({band})\n"
            f"Detected Signals:\n" + "\n".join([f"  * {r}" for r in reasons]) + "\n\n"
            f"5. ACTION REQUESTED FROM LAW ENFORCEMENT:\n"
            f"a) Immediate issuance of emergency blocking/suspension order under Section 69A IT Act to Domain Registrar and DoT/MeitY.\n"
            f"b) Notice under Section 91 CrPC / BNSS to Telecom Service Providers (TSPs) for CDR and subscriber CAF of suspect mobile numbers.\n"
            f"c) Immediate debit freeze on associated UPI VPAs and beneficiary bank accounts under Section 106 BNSS / 102 CrPC to prevent fund siphoning."
        )

        # 3. Police Memo for Bhavnagar / Gujarat Cyber Cell
        police_memo = (
            f"DIGITAL TRUST & SAFETY INITIATIVE — INCIDENT ESCALATION MEMORANDUM\n"
            f"Initiative from YatraDham.Org\n"
            f"Generated: {now_ist}\n\n"
            f"TARGET ENTITY: {host}\n"
            f"TARGETED INSTITUTION: {inst_name}\n"
            f"RISK LEVEL: {band} ({score}/100)\n"
            f"STATUTORY PROVISIONS: Sections 66C & 66D of Information Technology Act 2000; "
            f"Sections 318(4) & 319 BNS 2023 (Sec 419/420 IPC)\n\n"
            f"TECHNICAL SNAPSHOT:\n"
            f"- Primary Domain / URL: {target_url}\n"
            f"- Resolving IP: {ip} ({hosting_provider}, {country})\n"
            f"- Registrar: {registrar} (Abuse Desk: {abuse_email or 'pending'})\n"
            f"- Scammer Helplines: {', '.join(unauth_phones) if unauth_phones else 'See evidence packet'}\n"
            f"- Scammer UPI VPAs: {', '.join(upis) if upis else 'Direct UPI QR'}\n\n"
            f"EVIDENCE SUMMARY:\n" + "\n".join([f"- {r}" for r in reasons]) + "\n\n"
            f"RECOMMENDATION:\n"
            f"Escalate to Gujarat State Cyber Crime Cell / I4C Portal for priority takedown and SIM/VPA freeze."
        )

        # 4. Registrar Abuse Email Notice
        registrar_notice = (
            f"To: {abuse_email or 'abuse-desk@' + registrar.lower().replace(' ', '') + '.com'}\n"
            f"Subject: URGENT: Cease & Desist / Immediate Domain Suspension Request — {host} (Active Impersonation & Pilgrim Phishing Fraud)\n\n"
            f"Dear Abuse & Trust/Safety Team at {registrar},\n\n"
            f"We are writing on behalf of YatraDham.org (YatraDham E-Services Pvt Ltd) and the authorized management of {inst_name}.\n\n"
            f"We formally request the IMMEDIATE DE-REGISTRATION AND DNS SUSPENSION of domain name: '{host}' under ICANN Registrar "
            f"Accreditation Agreement (RAA) Section 3.18, and your Acceptable Use Policy regarding deceptive phishing, impersonation, "
            f"and online financial fraud.\n\n"
            f"Domain Details:\n"
            f"- Domain: {host}\n"
            f"- Host IP: {ip}\n"
            f"- Hosting Provider: {hosting_provider}\n"
            f"- Detection Date: {now_ist}\n\n"
            f"Evidence of Illegal Activity:\n"
            f"The registrant of '{host}' is intentionally impersonating {inst_name} and YatraDham.org to deceive religious pilgrims into "
            f"depositing fraudulent advance payments via unauthorized contact numbers ({', '.join(unauth_phones) if unauth_phones else 'displayed on domain'}) "
            f"and unauthorized payment links.\n\n"
            f"This constitutes criminal fraud under Sections 66C & 66D of the IT Act 2000 and Section 318(4) of the Bharatiya Nyaya Sanhita. "
            f"A formal criminal complaint has also been logged with the National Cyber Crime Reporting Portal (cybercrime.gov.in).\n\n"
            f"Failure to act upon this verified abuse report may result in secondary liability under intermediary guidelines. "
            f"Please confirm domain suspension by reply to legal@yatradham.org.\n\n"
            f"Sincerely,\n"
            f"Digital Trust & Legal Compliance Desk\n"
            f"YatraDham.org (YatraDham E-Services Pvt Ltd)\n"
            f"Bhavnagar, Gujarat, India\n"
            f"Contact: legal@yatradham.org | +91-278-2511111"
        )

        # 5. NIXI Notice (if .in / .co.in)
        nixi_notice = ""
        if host.endswith((".in", ".co.in", ".org.in", ".net.in")):
            nixi_notice = (
                f"To: registry@nixi.in, complaint@nixi.in\n"
                f"Subject: Emergency Request for Domain Suspension under .IN Anti-Abuse Policy — {host}\n\n"
                f"Respected NIXI Registry Team,\n\n"
                f"We hereby report an active cyber financial fraud occurring on the .IN domain '{host}', "
                f"registered through {registrar}.\n\n"
                f"The domain is impersonating '{inst_name}' and defrauding Indian pilgrims by collecting fraudulent room booking "
                f"deposits. We request immediate DNS hold/suspension under the .IN Registry Anti-Abuse Policy to protect the general public.\n\n"
                f"Technical details: IP: {ip} | Host: {hosting_provider} | Registered: {created_date}\n\n"
                f"Formal NCRP reference has been logged under Initiative from YatraDham.Org."
            )

        # 6. NPCI Bank / UPI Freeze Request
        npci_notice = ""
        if upis:
            npci_notice = (
                f"URGENT: Request for Freezing Fraudulent UPI VPA / Merchant Account\n"
                f"To: NPCI Cyber Cell & Beneficiary Bank Nodal Officer\n"
                f"Generated: {now_ist}\n\n"
                f"Reported UPI VPAs: {', '.join(upis)}\n"
                f"Associated Impersonating Domain: {target_url}\n"
                f"Victim Demographic: Religious pilgrims booking stays at {inst_name}\n\n"
                f"Modus Operandi: Scammers publish this UPI VPA on fake booking portals and instruct pilgrims to send token advance payments "
                f"via PhonePe/GooglePay/Paytm. We request immediate freeze on these accounts under RBI and NPCI Anti-Fraud Directives."
            )

        # 7. Chakshu DoT Telecom Blacklisting Format
        chakshu_report = ""
        if unauth_phones:
            chakshu_report = (
                f"DEPARTMENT OF TELECOMMUNICATIONS (DoT) — SANCHAR SAATHI / CHAKSHU INCIDENT REPORT\n"
                f"Report Category: Suspected Cyber Financial Fraud via Mobile Communications / WhatsApp\n"
                f"Reporting Agency: YatraDham.Org Digital Trust & Safety Desk\n"
                f"Report Date: {now_ist}\n\n"
                f"SUSPECT FRAUDULENT MOBILE NUMBERS IDENTIFIED:\n"
                + "\n".join([f"- Mobile Number: {ph} | Context: Listed as fake Ashram reservation manager on {target_url}" for ph in unauth_phones])
                + f"\n\nMODUS OPERANDI:\n"
                f"These numbers are actively engaged in defrauding devotees by soliciting advance booking tokens for {inst_name}. "
                f"Upon receipt of payment, devotees are blocked and booking is never honored.\n\n"
                f"STATUTORY REQUEST TO DoT / TSPs:\n"
                f"1. Immediate disconnection of all reported MSISDNs under Section 19 of the Telecommunications Act 2023.\n"
                f"2. Blocking of associated IMEI device IDs across all Indian telecom networks to prevent SIM swapping."
            )

        # 8. Google Safe Browsing Link
        safebrowsing_url = f"https://safebrowsing.google.com/safebrowsing/report_phish/?url={quote_plus(target_url)}"

        return TakedownDossier(
            complaint_subject=subject,
            police_memo=police_memo,
            registrar_abuse_notice=registrar_notice,
            nixi_notice=nixi_notice,
            npci_bank_freeze_request=npci_notice,
            chakshu_dot_report=chakshu_report,
            google_safebrowsing_url=safebrowsing_url,
            target_summary=f"{host} ({inst_name} - Score {score}/100 {band})"
        )
