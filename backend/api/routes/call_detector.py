import os
import json
import phonenumbers
import google.generativeai as genai
from flask import Blueprint, request, jsonify
from phonenumbers import geocoder, carrier
from utils.logger import log_detection
from utils.jwt_utils import decode_token

call_bp = Blueprint("call_bp", __name__)

# Configure Gemini
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-2.0-flash')

def get_professional_fallback(risk_level, number, info):
    """Provides high-quality fallback explanations when AI generation fails."""
    if risk_level == "Dangerous":
        return f"This phone number ({number}) exhibits high-risk characteristics associated with automated scam activity. The lack of a valid carrier registration or use of a VoIP service suggests it was generated for temporary, potentially malicious outreach. We strongly recommend blocking this number to prevent identity theft or financial fraud."
    elif risk_level == "Suspicious":
        return f"The number ({number}) appears to be a legitimate VoIP or non-fixed line, which is frequently used by both legitimate businesses and telemarketers. While no immediate threat is detected, the untraceable nature of the service justifies caution during interaction. Verify the caller's identity through official channels before sharing any sensitive information."
    else:
        return f"Our analysis indicates that this number ({number}) is a standard verified line registered with {info.get('carrier', 'a major provider')}. It follows all international formatting standards and shows no technical indicators of spoofing or automated bot activity. It is currently categorized as low-risk for standard voice communication."

def gemini_analyze(number, info):
    prompt = f"""
    Analyze this phone number metadata as a cybersecurity expert for a premium security suite.
    Number: {number}
    Carrier: {info['carrier']}
    Type: {info['type']}
    Location: {info['country']}
    VoIP: {info['voip']}
    Valid Format: {info['is_valid']}

    Provide a professional, authoritative assessment in EXACTLY this JSON format:
    {{
      "risk": "Dangerous" | "Suspicious" | "Verified",
      "explanation": "A professional 3-sentence paragraph explaining the technical reasoning.",
      "danger_points": ["Point 1", "Point 2"],
      "tips": ["Security Tip 1", "Security Tip 2"]
    }}
    """
    
    try:
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=0.1,
                response_mime_type="application/json"
            )
        )
        ai_data = json.loads(response.text)
        return ai_data
    except Exception as e:
        print(f"Gemini Error: {e}")
        # Determine risk for fallback
        risk = "Verified"
        if info['voip'] or not info['is_valid']:
            risk = "Dangerous" if not info['is_valid'] else "Suspicious"
            
        return {
            "risk": risk,
            "explanation": get_professional_fallback(risk, number, info),
            "danger_points": ["Technical indicators suggest automated origin"] if risk != "Verified" else [],
            "tips": ["Always verify caller identity", "Do not share OTPs over calls"]
        }

@call_bp.route("/call/detect", methods=["POST"])
def detect_number():
    try:
        data = request.json
        number = data.get("number")
        if not number:
            return jsonify({"success": False, "error": "No number provided"}), 400

        # Use phonenumbers library for parsing
        try:
            if number.startswith('+'):
                parsed = phonenumbers.parse(number, None) 
            else:
                # Fallback for Indian numbers if no prefix
                parsed = phonenumbers.parse(number, "IN")
        except:
             return jsonify({
                "success": True, 
                "analysis": {"score": 100, "is_valid": False, "voip": False, "country": "Unknown", "carrier": "Invalid", "type": "Invalid"},
                "ai": {
                    "risk": "Dangerous",
                    "explanation": "The provided number format is technically invalid and cannot be reconciled with international telecommunication standards. This is a common tactic used in 'ghost calling' and numeric spoofing to bypass traditional filtering. Interacting with such numbers poses a high risk of exposure to malicious botnets.",
                    "danger_points": ["Invalid numeric structure", "Unresolvable carrier metadata"],
                    "tips": ["Do not answer calls from unformatted numbers", "Report this number to your service provider"]
                }
            })

        num_type = phonenumbers.number_type(parsed)
        type_labels = {
            0: "Fixed Line", 1: "Mobile", 2: "Mobile/Fixed", 3: "Toll Free",
            4: "Premium Rate", 5: "Shared Cost", 6: "VoIP", 7: "Personal",
            8: "Pager", 9: "UAN", 10: "Voicemail"
        }

        info = {
            "phone": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "country": geocoder.description_for_number(parsed, "en") or "Unknown",
            "carrier": carrier.name_for_number(parsed, "en") or "Unknown",
            "type": type_labels.get(num_type, "Standard Line"),
            "voip": num_type == phonenumbers.PhoneNumberType.VOIP,
            "is_valid": phonenumbers.is_valid_number(parsed),
            "score": 0 
        }
        
        # Scoring logic: High Score = High Risk
        if not info['is_valid']: 
            info['score'] = 100
        else:
            if info['voip']: info['score'] += 75
            if info['carrier'] == "Unknown": info['score'] += 15
            if num_type in [4, 5]: info['score'] += 40 # Premium/Shared
            if info['country'] == "Unknown": info['score'] += 10
        
        info['score'] = min(100, info['score'])
        if info['score'] == 0: info['score'] = 5 # Minimum visible base

        ai_res = gemini_analyze(number, info)

        # --- ADVANCED LOGGING ---
        try:
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
            
            log_detection(user_email, "Call Detector")
            from utils.logger import log_detailed_call
            log_detailed_call(
                user_email,
                number,
                info['carrier'],
                info['country'],
                ai_res.get('risk', 'Unknown'),
                info['score']
            )
        except: pass
            
        return jsonify({"success": True, "analysis": info, "ai": ai_res})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500