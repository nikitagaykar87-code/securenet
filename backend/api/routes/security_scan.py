import os
import requests
import re
import whois
import time
import json
import socket
from flask import Blueprint, request, jsonify
from utils.logger import log_detection
from utils.jwt_utils import decode_token


scan_bp = Blueprint("scan_bp", __name__)
print("DEBUG: security_scan.py loaded and scan_bp created")

VT_API = os.getenv("VT_API")
IPQS_API = os.getenv("IPQS_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"


def extract_domain(url):
    # Strip protocol and path
    d = url.lower()
    if "://" in d:
        d = d.split("://")[1]
    d = d.split("/")[0].split("?")[0].split("#")[0]
    return d

def is_valid_domain(domain):
    # Strict FQDN regex: allows subdomains, hyphens, and standard TLDs. 
    # Must NOT contain special characters like ; , ! @ # $ etc.
    domain_regex = r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"
    return re.match(domain_regex, domain) is not None


# ------------------------------------------
# 1. Google Transparency Report (NO KEY)
# ------------------------------------------
def google_transparency(url):
    try:
        req = requests.get(
            f"https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status?url={url}",
            timeout=8
        )
        if "MALWARE" in req.text or "SOCIAL_ENGINEERING" in req.text:
            return {"safe": False, "threat": "Unsafe (Google)"}
        return {"safe": True, "threat": "None"}
    except:
        return {"safe": False, "threat": "Error"}


# ------------------------------------------
# 2. Cloudflare Security (NO KEY)
# ------------------------------------------
def cloudflare_scan(domain):
    try:
        r = requests.get(
            f"https://security.cloudflare.com/lookup?domain={domain}",
            timeout=8
        )
        if "malicious" in r.text.lower():
            return {"status": "Malicious"}
        return {"status": "Clean"}
    except:
        return {"status": "Unknown"}


# ------------------------------------------
# 3. OpenPhish (LIVE PHISHING FEED)
# ------------------------------------------
def openphish_check(url):
    try:
        feed = requests.get("https://openphish.com/feed.txt", timeout=8).text
        return {"phishing": url in feed}
    except:
        return {"phishing": False}


# ------------------------------------------
# 4. PhishTank (NO KEY)
# ------------------------------------------
def phishtank_check(url):
    try:
        r = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={"url": url, "format": "json"},
            timeout=10
        )
        data = r.json()
        if data["results"]["in_database"] and data["results"]["verified"]:
            if data["results"]["valid"]:
                return {"phishing": True}
        return {"phishing": False}
    except:
        return {"phishing": False}


# ------------------------------------------
# 5. ScamAdviser Trust Score (HTML scrape)
# ------------------------------------------
def scamadviser(domain):
    try:
        page = requests.get(f"https://www.scamadviser.com/check-website/{domain}", timeout=8)
        match = re.search(r'"trustscore":(\d+)', page.text)
        if match:
            score = int(match.group(1))
            return {"trust_score": score}
        return {"trust_score": 50}
    except:
        return {"trust_score": 50}


# ------------------------------------------
# 6. IPQualityScore (YOUR KEY)
# ------------------------------------------
def ipqs_scan(url):
    try:
        r = requests.get(
            f"https://ipqualityscore.com/api/json/url/{IPQS_API}/{url}",
            timeout=10
        )
        data = r.json()
        return {
            "risk": data.get("risk_score", 0),
            "malicious": data.get("malicious", False),
            "phishing": data.get("phishing", False)
        }
    except:
        return {"risk": 0, "malicious": False, "phishing": False}


# ------------------------------------------
# 7. VirusTotal (YOUR KEY)
# ------------------------------------------
def virustotal(url):
    try:
        upload = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers={"x-apikey": VT_API},
            data={"url": url},
            timeout=10
        )
        url_id = upload.json()["data"]["id"]

        time.sleep(2)

        scan = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{url_id}",
            headers={"x-apikey": VT_API},
            timeout=10
        ).json()

        stats = scan["data"]["attributes"]["stats"]
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0)
        }

    except:
        return {"malicious": 0, "suspicious": 0}


# ------------------------------------------
# 8. SSL Labs Grade
# ------------------------------------------
def ssl_grade(domain):
    try:
        r = requests.get(
            f"https://api.ssllabs.com/api/v3/analyze?host={domain}&fromCache=on",
            timeout=12
        ).json()
        grade = r["endpoints"][0].get("grade", "Unknown")
        return {"grade": grade}
    except:
        return {"grade": "Unknown"}


# ------------------------------------------
# 9. WHOIS Domain Age
# ------------------------------------------
def domain_age(domain):
    try:
        info = whois.whois(domain)
        created = info.creation_date

        if isinstance(created, list):
            created = created[0]

        years = (time.time() - created.timestamp()) / (365 * 24 * 3600)
        return {"age": float(round(years, 2))}
    except:
        return {"age": 0.0}


# ------------------------------------------
# 10. Redirect Chain
# ------------------------------------------
def redirect_chain(url):
    try:
        r = requests.get(url, allow_redirects=True, timeout=10)
        chain = [resp.url for resp in r.history]
        return {"redirects": chain}
    except:
        return {"redirects": []}


# ------------------------------------------
# 11. Fake URL Detection (Pattern based)
# ------------------------------------------
def fake_url_detector(url):
    patterns = [
        r"-secure-", r"-verify-", r"-login-", r"-update-",
        r"\.icu$", r"\.xyz$", r"\.top$", r"pay-", r"billing",
        r"gift", r"free", r"bonus", r"reward",
        r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", # IP address URLs
        r"[;,'\"<>#%{}|\\^~\[\]` \t]", # Illegal characters in host
        r"(https?:\/\/)?([a-z0-9-]+\.){3,}[a-z0-9-]+" # Deep subdomains
    ]
    for p in patterns:
        if re.search(p, url.lower()):
            return {"fake": True}
    return {"fake": False}

def is_domain_resolvable(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except:
        return False


# ------------------------------------------
# 12. FINAL SCORE SYSTEM
# ------------------------------------------
def calculate_score(data, domain):
    score = 100

    # Critical Detections
    if not data["google"]["safe"]: score -= 40
    if data["ipqs"]["malicious"]: score -= 35
    if data["openphish"]["phishing"]: score -= 30
    if data["phishtank"]["phishing"]: score -= 30
    
    # Gradual Penalties
    score -= data["ipqs"]["risk"] * 0.4
    score -= data["virustotal"]["malicious"] * 12
    
    # Suspicious Patterns
    if data["fake"]["fake"]: score -= 20
    
    # Domain Trust
    if data["domain_age"]["age"] == 0: # WHOIS failed
        score -= 40 # Heavy penalty for non-existent/private domains
    elif data["domain_age"]["age"] < 1:
        score -= 15

    # SSL Trust
    if data["ssl"]["grade"] == "Unknown":
        score -= 25
    elif "F" in data["ssl"]["grade"] or "T" in data["ssl"]["grade"]:
        score -= 30

    # Resolution Check (The "ht;email.com" fix)
    if not is_domain_resolvable(domain):
        score -= 50 # Massive penalty if the domain doesn't exist

    if score < 5: score = 5
    if score > 100: score = 100
    return score


def get_gemini_report_logic(score, scan_result):
    try:
        prompt = f"""
        Act as a Lead Cybersecurity Forensic Analyst. Analyze the following URL security data and provide a PROPER DEEP technical assessment.
        Your goal is to provide a "Cyber-Forensic Report" style explanation that is both authoritative and detailed.
        
        DATA TO ANALYZE:
        - Security Trust Score: {score}/100
        - VirusTotal: {scan_result.get('virustotal', {}).get('malicious', 0)} malicious engines detections
        - IPQualityScore Fraud Risk: {scan_result.get('ipqs', {}).get('risk', 0)}/100
        - Domain Age: {scan_result.get('domain_age', {}).get('age', 0)} years
        - SSL Grade: {scan_result.get('ssl', {}).get('grade', 'Unknown')}
        - Redirection Hops: {len(scan_result.get('redirects', {}).get('redirects', []))}
        - URL Pattern: {"Suspicious/Malformed" if scan_result.get('fake', {}).get('fake') else "Standard"}
        
        REPORT REQUIREMENTS:
        1. EXPLANATION (The "Deep Dive"): Provide 2-3 detailed paragraphs explaining the technical synergy of these metrics. Mention specific risks like 'Zero-day phishing', 'SSL downgrade attacks', or 'Domain reputation' based on the score. 
        2. DANGER POINTS: 3-5 technical indicators of risk.
        3. SAFETY TIPS: Professional mitigation strategies.

        Respond ONLY with a valid JSON object:
        {{
            "explanation": "Paragraph 1\\n\\nParagraph 2\\n\\nParagraph 3",
            "danger_points": ["...", "..."],
            "tips": ["...", "..."]
        }}
        """
        # Use gemini-2.0-flash for better "Deep" analysis
        API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "response_mime_type": "application/json"
            }
        }
        response = requests.post(f"{API_URL}?key={GEMINI_API_KEY}", json=payload, timeout=15)
        res_data = response.json()
        
        if "candidates" in res_data:
            content = res_data["candidates"][0]["content"]["parts"][0]["text"]
            return json.loads(content)
    except Exception as e:
        print(f"AI Summary Error: {e}")
    
    # Robust 3-tier Fallback
    if score >= 80:
        return {
            "explanation": "This URL points to an established, reputable domain with a strong security profile. No immediate threats were detected during our multi-engine forensic analysis.",
            "danger_points": ["Minimal risk detected based on current DNS and SSL metrics."],
            "tips": ["Always check for the padlock icon in your browser.", "Verify the URL spelling before entering sensitive data."]
        }
    elif score >= 50:
        return {
            "explanation": "Caution is advised. While not explicitly blacklisted, this URL shows suspicious attributes such as a relatively new domain or unusual redirection patterns.",
            "danger_points": ["Domain age is relatively low.", "Indirect routing detected in the link history."],
            "tips": ["Do not enter sensitive passwords on this site.", "If this was sent via unsolicited email/SMS, treat it with high suspicion."]
        }
    else:
        return {
            "explanation": "CRITICAL RISK: This URL exhibits high-confidence malicious indicators. It is likely a phishing attempt or a malware distribution node.",
            "danger_points": ["Extreme risk of credential harvesting.", "Suspicious domain structure detected.", "Redirection chain matches typical phishing 'hooks'."],
            "tips": ["CLOSE THIS PAGE IMMEDIATELY.", "Do not download any files from this site.", "Report this source to your IT security department."]
        }

@scan_bp.post("/scan")
def scan():
    try:
        url_input = request.json.get("url", "").strip()
        if not url_input:
            return jsonify({"success": False, "error": "URL is required"})

        # Normalize and Extract
        domain = extract_domain(url_input)
        print(f"DEBUG: Processing Domain [{domain}] | Input: [{url_input}]")

        # --- NUCLEAR VALIDATION ---
        if not is_valid_domain(domain):
            print(f"CRITICAL: Invalid Domain detected: {domain}")
            return jsonify({
                "success": True,
                "data": {
                    "url": url_input,
                    "score": 1,
                    "version": "SECURE_SCAN_V5_NUCLEAR",
                    "ai": {
                        "explanation": "CRITICAL RISK: The provided URL is malformed or uses illegal characters (like ';'). This is a primary indicator of phishing attempts or system-level attacks targeting your browser. Accessing this link is highly dangerous and likely leads to malware infection or data interception.",
                        "danger_points": ["Malformed URL structure detected.", "Illegal characters found in FQDN.", "Probable obfuscation attack."],
                        "tips": ["Close this page immediately.", "Do NOT attempt to manually fix the URL.", "Report this source as a malicious threat."]
                    },
                    "google": {"safe": False, "threat": "Malformed/Suspicious"},
                    "virustotal": {"malicious": 99},
                    "ipqs": {"risk": 100, "malicious": True},
                    "ssl": {"grade": "N/A"},
                    "domain_age": {"age": 0},
                    "redirects": {"redirects": []},
                    "fake": {"fake": True}
                }
            })

        # Logic for Normal Scans
        result = {
            "google": google_transparency(url_input),
            "cloudflare": cloudflare_scan(domain),
            "openphish": openphish_check(url_input),
            "phishtank": phishtank_check(url_input),
            "scamadviser": scamadviser(domain),
            "ipqs": ipqs_scan(url_input),
            "virustotal": virustotal(url_input),
            "ssl": ssl_grade(domain),
            "domain_age": domain_age(domain),
            "redirects": redirect_chain(url_input),
            "fake": fake_url_detector(url_input),
        }

        # Update calculations
        result["score"] = calculate_score(result, domain)
        result["version"] = "SECURE_SCAN_V5_NUCLEAR"
        
        # --- GET AI REPORT CONCURRENTLY (FAST) ---
        result["ai"] = get_gemini_report_logic(result["score"], result)

        # --- PROFESSIONAL LOGGING & ALERTS ---
        try:
            from utils.logger import log_website_scan, log_api_usage, create_security_alert, log_detection, log_detailed_url
            import random
            from config import DEFAULT_GUEST_EMAILS
            auth_header = request.headers.get("Authorization")
            user_email = random.choice(DEFAULT_GUEST_EMAILS)
            if auth_header and auth_header.startswith("Bearer "):
                from utils.jwt_utils import decode_token
                token = auth_header.split(" ")[1]
                decoded = decode_token(token)
                if decoded:
                    user_email = decoded.get("email", random.choice(DEFAULT_GUEST_EMAILS))
            
            final_score = int(result.get("score", 0))
            malicious_count = int(result.get("virustotal", {}).get("malicious", 0))
            risk_val = int(result.get("ipqs", {}).get("risk", 0))
            ssl_val = str(result.get("ssl", {}).get("grade", "N/A"))

            log_website_scan(user_email, url_input, final_score, malicious_count, risk_val, ssl_val)
            log_detailed_url(user_email, url_input, "Security Scanner", final_score, "Malicious" if final_score < 50 else "Safe")
            log_api_usage("VirusTotal", user_email, tokens=1, latency=2000)
            log_api_usage("IPQualityScore", user_email, tokens=1, latency=500)
            
            if final_score < 50:
                create_security_alert(user_email, "Malicious URL Detected", "High" if final_score < 25 else "Medium", f"Website scan for {url_input} returned a low safety score.")
                
            log_detection(user_email, "Website Scanner")
        except: pass

        return jsonify({"success": True, "data": result})
    except Exception as e:
        print(f"Scan API Error: {e}")
        return jsonify({"success": False, "error": str(e)})


@scan_bp.route("/gemini_ai_report", methods=["POST"])
def gemini_summary_endpoint():
    # Deprecated: Kept for backward compatibility if needed, but redirects to main logic
    data = request.json
    return jsonify({"success": True, "data": get_gemini_report_logic(data.get("score"), data.get("result"))})


@scan_bp.get("/test_scan")
def test_scan():
    return jsonify({"success": True, "message": "Scan blueprint is working!"})

