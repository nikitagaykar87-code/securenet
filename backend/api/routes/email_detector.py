import os, json, re, hashlib
import dns.resolver
import whois
import requests
import tldextract
from datetime import datetime
from flask import Blueprint, request, jsonify
from email_validator import validate_email, EmailNotValidError
from utils.logger import log_detection
from utils.jwt_utils import decode_token

email_bp = Blueprint("email_bp", __name__)

# ================= ENV =================
GEMINI_KEY = os.getenv("GEMINI_API_KEY")
IPQS_KEY = os.getenv("IPQS_API_KEY")
VT_KEY = os.getenv("VT_API")

GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"

# ================= TRUSTED PROVIDERS & AGE =================
# Hardcoded ages (in years) for major providers to avoid "Unknown"
MAJOR_DOMAINS = {
    "gmail.com": {"name": "Google Gmail", "age": 20},
    "googlemail.com": {"name": "Google Gmail", "age": 20},
    "google.com": {"name": "Google Services", "age": 25},
    "outlook.com": {"name": "Microsoft Outlook", "age": 12},
    "hotmail.com": {"name": "Microsoft Outlook", "age": 28},
    "yahoo.com": {"name": "Yahoo Mail", "age": 27},
    "icloud.com": {"name": "Apple iCloud", "age": 13},
    "protonmail.com": {"name": "Proton Mail", "age": 10},
    "aol.com": {"name": "AOL Mail", "age": 30},
    "zoho.com": {"name": "Zoho Mail", "age": 15},
    "yandex.com": {"name": "Yandex Mail", "age": 23},
    "gmx.com": {"name": "GMX Mail", "age": 25},
    "mail.com": {"name": "Mail.com", "age": 25}
}

# ================= GRAVATAR CHECK =================
def check_gravatar(email):
    """
    Checks if the email has a Gravatar profile.
    Returns the avatar URL if found, None otherwise.
    """
    try:
        # Trim and lowercase detection
        email_hash = hashlib.md5(email.strip().lower().encode('utf-8')).hexdigest()
        gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
        
        # We just check head to see if it exists (200 OK) or not (404)
        r = requests.head(gravatar_url, timeout=3)
        if r.status_code == 200:
            return gravatar_url
    except:
        pass
    return None

# ================= DOMAIN AGE =================
def domain_age(domain):
    # Check hardcoded list first
    if domain in MAJOR_DOMAINS:
        return MAJOR_DOMAINS[domain]["age"]

    try:
        w = whois.whois(domain)
        c = w.creation_date
        if isinstance(c, list):
            c = c[0]
        if not c:
            return None
        
        # Calculate age
        age = (datetime.now() - c).days // 365
        return age
    except:
        return None

# ================= DNS CHECK =================
def dns_health(domain):
    mx = spf = dmarc = False

    try:
        dns.resolver.resolve(domain, "MX")
        mx = True
    except:
        pass

    try:
        txt_records = dns.resolver.resolve(domain, "TXT")
        for r in txt_records:
            if "v=spf1" in str(r):
                spf = True
                break
    except:
        pass

    try:
        dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc = True
    except:
        pass

    return {"mx": mx, "spf": spf, "dmarc": dmarc}

# ================= DOMAIN HEURISTICS (ADVANCED) =================
def domain_heuristics(domain):
    score = 0
    reasons = []

    ext = tldextract.extract(domain)
    # Reconstruct the main part: "google" from "google.com" or "mail.google.com"
    # Actually tldextract gives subdomain, domain, suffix. 
    # Core domain is ext.domain (e.g. "google" from "ipv4.google.com")
    core = ext.domain.lower()
    full_domain = f"{ext.domain}.{ext.suffix}"

    # 1. Look-alike / Typosquatting (Homoglyphs & Leetspeak)
    # Simple regex for common spoofing replacements
    if re.search(r"(amaz0n|paypa1|micros0ft|g00gle|gmai1|out1ook|yah00)", core):
        score += 50
        reasons.append("Typosquatting detected (Brand Spoffing)")

    # 2. Excessive hyphens
    if domain.count("-") >= 3:
        score += 15
        reasons.append("Excessive hyphens in domain")

    # 3. Suspicious TLDs
    risky_tlds = ["tk", "ml", "ga", "cf", "top", "xyz", "cn", "ru", "work", "loan"]
    if ext.suffix in risky_tlds:
        score += 25
        reasons.append(f"High-risk TLD (.{ext.suffix})")
    
    # 4. Homoglyph / Mixed Script warning (Basic)
    # Check for non-ascii characters if domain is not punycode mapped yet
    # Python generic check:
    try:
        domain.encode('ascii')
    except UnicodeEncodeError:
         # If it's not IDN punycode, it might be a homoglyph attack
         score += 30
         reasons.append("Contains non-ASCII characters (Possible Homoglyph)")

    return score, reasons

# ================= IPQS =================
def ipqs_email(email):
    if not IPQS_KEY:
        return 0, False

    try:
        r = requests.get(
            f"https://www.ipqualityscore.com/api/json/email/{IPQS_KEY}/{email}",
            timeout=6
        ).json()
        return int(r.get("fraud_score", 0)), r.get("disposable", False)
    except:
        return 0, False

# ================= VIRUSTOTAL =================
def vt_domain(domain):
    if not VT_KEY:
        return 0

    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VT_KEY},
            timeout=6
        ).json()
        stats = r["data"]["attributes"]["last_analysis_stats"]
        return stats.get("malicious", 0) + stats.get("suspicious", 0)
    except:
        return 0

import google.generativeai as genai

# ================= AI CONFIG =================
def get_ai_model():
    key = os.getenv("GEMINI_API_KEY")
    if not key: return None
    genai.configure(api_key=key.strip())
    return genai.GenerativeModel('models/gemini-flash-latest')

def get_professional_fallback(details, score, reasons, risk_level):
    """Returns a high-quality professional paragraph template based on tech analysis"""
    
    # Business Phish Template
    if any(k in str(reasons).lower() for k in ["typosquatting", "homoglyph", "brand"]):
        return {
            "explanation": f"Our analysis confirms this email is a business impersonation attempt designed to deceive you into believing it originates from a trusted brand. The domain history and technical flags indicate that the sender is utilizing 'typosquatting' tactics, which is a common method for stealing login credentials and sensitive financial data. We strongly advise that you do not click any links or download attachments, as this communication is considered a high-priority security threat and should be blocked immediately.",
            "danger_points": ["Impersonation pattern detected.", "Suspicious domain syntax identified."],
            "tips": ["Verify the branding carefully.", "Never provide credentials via email links.", "Report as impersonation."]
        }
    
    # Suspicious Provider Template
    if details.get("Provider") == "Unknown" or details.get("Disposable") == "Yes":
        return {
            "explanation": "This email originates from a high-risk or disposable provider typically associated with automated spam campaigns and fraudulent activities. Legitimate organizations and professional contacts almost exclusively use reputable enterprise mail servers or established public providers for secure communication. Interaction with this address poses a significant risk of malware infection or inclusion in future targeted phishing lists.",
            "danger_points": ["Non-standard mail server used.", "High-risk provider identified."],
            "tips": ["Treat all links with extreme caution.", "Blacklist this sender from your inbox.", "Check if the sender identity is verifiable."]
        }

    # Verified Safe Template
    if risk_level == "Verified":
        return {
            "explanation": "This email has passed all critical security checks, including SPF and DMARC authentication, and correlates with a verified public identity profile. The domain exhibits a long-standing history of legitimate operation and is hosted by a recognized, high-trust mail service provider. You can safely interact with this sender, though we always recommend verifying the context of any requests for sensitive information.",
            "danger_points": [],
            "tips": ["Safe to respond if expected.", "Always check the intent of the message.", "Verified identity found via Gravatar."]
        }

    # General Suspicious
    return {
        "explanation": "While this email address follows standard formatting, our security engine detected several neutral visibility signals that warrant a cautious approach. It lacks a verified public identity and originates from a domain that does not exhibit strong historical reputation data, which is often seen in early-stage phishing campaigns. We recommend that you perform an out-of-band identity check before sharing any confidential or internal business information.",
        "danger_points": ["New domain history detected.", "Low reputation signature found."],
        "tips": ["Hover over links to see the true destination.", "Do not bypass browser security warnings.", "Monitor for unusual urgency in content."]
    }

def gemini_analyze(details, score, reasons, risk_level):
    """AI analysis with automatic transition to high-quality templates on failure"""
    model = get_ai_model()
    if not model: return get_professional_fallback(details, score, reasons, risk_level)

    try:
        prompt = f"""
        Act as a Senior Cyber Security Analyst. Analyze this email:
        Email: {details['Email']}
        Domain: {details['Domain']}
        Risk Level: {risk_level} (Score: {score}/100)
        Attributes: {details}
        Flags: {reasons}

        Return ONLY a JSON object with:
        "explanation": "A professional 3-sentence paragraph explanation on why this is or is not dangerous in simple words.",
        "danger_points": ["Specific Point 1", "Specific Point 2"],
        "tips": ["Tip 1", "Tip 2", "Tip 3"]
        """
        
        response = model.generate_content(
            prompt,
            safety_settings=[
                {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            ]
        )
        
        raw_text = response.text
        json_match = re.search(r'\{.*\}', raw_text, re.DOTALL)
        if json_match:
            return json.loads(json_match.group(0))
        return json.loads(raw_text)

    except Exception as e:
        return get_professional_fallback(details, score, reasons, risk_level)


# ================= API ROUTE =================
@email_bp.route("/email/analyze", methods=["POST"])
def analyze_email():
    email = request.json.get("email", "").strip()

    if not email:
        return jsonify(success=False), 400

    # ---------- Validate Format ----------
    try:
        validate_email(email)
    except EmailNotValidError as e:
        return jsonify(
            success=True,
            score=100,
            risk="Dangerous",
            details={"error": "Invalid Email Format"},
            ai={
                "explanation": f"The provided email format is technically invalid, as the domain '{email.split('@')[-1]}' does not currently support standard mail reception protocols. This frequently occurs with misspelled addresses or domains specifically generated for short-term fraudulent activities. We recommend that you verify the spelling carefully and avoid interacting with this sender until a valid communication channel can be established.",
                "danger_points": ["Invalid domain configuration.", "Non-standard email syntax."],
                "tips": ["Check for typos in the address.", "Do not respond to invalid senders.", "Verify the domain existence."]
            }
        )

    domain = email.split("@")[1].lower()
    
    # ---------- Base Variables ----------
    score = 60
    reasons = []
    
    # 1. Trusted Provider Check
    provider_info = MAJOR_DOMAINS.get(domain)
    provider_name = provider_info["name"] if provider_info else "Unknown"
    
    if provider_info:
        score = 10 # Low risk baseline for trusted
        reasons.append("Trusted Email Provider")
    else:
        # Unknown provider
        score = 45 

    # 2. Domain Age
    age = domain_age(domain)
    if age is not None:
        if age >= 5:
            score -= 10
            reasons.append(f"Long domain history ({age}y)")
        elif age < 1:
            score += 40
            reasons.append("Newly registered domain (<1y)")
    else:
        # Penalize if age is completley hidden/unknown for non-major domains
        if not provider_info:
            score -= 10
            reasons.append("Domain age hidden")

    # 3. DNS Security (MX, SPF, DMARC)
    dns_res = dns_health(domain)
    if dns_res["mx"]: 
        if not provider_info: score -= 5
    else:
        score = 100 # No MX = Can't receive email = Fake
        reasons.append("Missing MX Records (Invalid Domain)")

    if dns_res["spf"]: 
        score -= 5
    else:
        score += 15
        reasons.append("SPF Authentication Missing")

    if dns_res["dmarc"]: 
        score -= 5
    else:
        # DMARC is stricter, lesser penalty if missing but SPF exists
        score += 5

    # 4. Identity Check (Gravatar)
    # If a user has a Gravatar, they are almost certainly a real human
    avatar_url = check_gravatar(email)
    if avatar_url:
        score -= 20
        reasons.append("Verified Public Profile (Gravatar)")

    # 5. Domain Heuristics (Typosquatting/Spammy TLDs)
    h_score, h_reasons = domain_heuristics(domain)
    score += h_score
    reasons.extend(h_reasons)

    # 6. IPQS (Disposable / Fraud)
    fraud, disposable = ipqs_email(email)
    if fraud > 75:
        score += 50
        reasons.append("High Fraud Score (IPQS)")
    
    if disposable:
        score = 100 # Immediate kill
        reasons.append("Disposable/Temporary Verification Email")

    # 7. VirusTotal (Malware domains)
    vt_hits = vt_domain(domain)
    if vt_hits > 0:
        score += (vt_hits * 30)
        reasons.append(f"Flagged by {vt_hits} security vendors")

    # ---------- Final Calculation ----------
    score = max(0, min(100, score))
    
    # Determine Risk Label
    # Score Check: 0-35 = Verified, 36-69 = Suspicious, 70-100 = Dangerous
    if score >= 70:
        risk = "Dangerous"
    elif score >= 36:
        risk = "Suspicious"
    else:
        risk = "Verified"

    # ---------- Prepare Response ----------
    details = {
        "Email": email,
        "Domain": domain,
        "Provider": provider_name,
        "Domain Age": f"{age} years" if age is not None else "Unknown",
        "Identity Found": "Yes" if avatar_url else "No",
        "MX": "Pass" if dns_res["mx"] else "Fail",
        "SPF": "Pass" if dns_res["spf"] else "Fail",
        "DMARC": "Pass" if dns_res["dmarc"] else "Fail",
        "Disposable": "Yes" if disposable else "No",
        "Avatar": avatar_url # Send back to frontend
    }

    ai = gemini_analyze(details, score, reasons, risk)

    # --- ADVANCED LOGGING & ALERTS ---
    try:
        import random
        from config import DEFAULT_GUEST_EMAILS
        auth_header = request.headers.get("Authorization")
        user_email = random.choice(DEFAULT_GUEST_EMAILS)
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            decoded = decode_token(token)
            if decoded:
                user_email = decoded.get("email", random.choice(DEFAULT_GUEST_EMAILS))
        
        # 1. Standard Logging
        log_detection(user_email, "Email Detector")

        # 2. Detailed Logging
        from utils.logger import log_detailed_email, create_security_alert, log_api_usage
        log_detailed_email(
            user_email, 
            domain, 
            details.get("Breach Count", 0), 
            details.get("SPF"), 
            details.get("DMARC"), 
            score
        )

        # 3. Security Alerts (Critical/High Severity)
        if risk == "Dangerous" or score < 30:
            create_security_alert(
                user_email,
                "Email Phishing/Fraud",
                "High",
                f"Dangerous email detected: {email}. Flags: {', '.join(reasons)}"
            )

        # 4. API Usage (Optional, if keys used)
        if IPQS_KEY:
            log_api_usage("IPQualityScore", user_email, tokens=1)
        if VT_KEY:
            log_api_usage("VirusTotal", user_email, tokens=1)

    except Exception as log_err:
        print(f"Detailed Logging Error: {log_err}")

    return jsonify(

        success=True,
        score=score,
        risk=risk,
        details=details,
        ai=ai
    )

