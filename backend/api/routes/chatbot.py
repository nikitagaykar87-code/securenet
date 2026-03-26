from flask import Blueprint, request, jsonify
from dotenv import load_dotenv
import os
from google import genai

load_dotenv()

chatbot_bp = Blueprint("chatbot_bp", __name__)

api_key = os.getenv("GEMINI_API_KEY")

client = None
if api_key:
    client = genai.Client(api_key=api_key)
else:
    print("⚠️ WARNING: GEMINI_API_KEY not found. Chatbot disabled.")

@chatbot_bp.route("/chatbot/ask", methods=["POST"])
def chatbot_ask():

    if not client:
        return jsonify({
            "reply": "⚠️ SecureNet AI is not configured."
        }), 503

    data = request.get_json(silent=True) or {}
    message = data.get("message", "").strip()

    if not message:
        return jsonify({"reply": "Please type a message."}), 400

    prompt = f"""
You are SecureNet AI, a cyber safety assistant.
Answer clearly in plain text.

User question:
{message}
"""

    try:
        response = client.models.generate_content(
            model="gemini-1.5-flash",
            contents=prompt
        )
        return jsonify({"reply": response.text})

    except Exception as e:
        print("GEMINI ERROR:", e)
        return jsonify({
            "reply": "⚠️ SecureNet AI is temporarily unavailable."
        }), 503


@chatbot_bp.route("/chatbot/draft", methods=["POST"])
def chatbot_draft():
    if not client:
        return jsonify({"reply": "⚠️ SecureNet AI is not configured."}), 503

    data = request.get_json(silent=True) or {}
    incident_details = data.get("details", "").strip()

    if not incident_details:
        return jsonify({"reply": "Please provide incident details."}), 400

    prompt = f"""
    You are an expert legal aide for cybercrime victims in India.
    
    Task: Draft a formal complaint letter to the Bank Manager or Cyber Crime Cell based on these details:
    "{incident_details}"
    
    Format:
    - Subject Line
    - Salutation
    - Clear description of the incident
    - Request for immediate action (blocking account, freezing funds)
    - Sign-off
    - Placeholders for missing info like [Date], [Account Number], [Transaction ID] if not provided.
    
    Tone: Formal, urgent, and professional.
    Output: Plain text only, no markdown formatting like bold or italics.
    """

    try:
        response = client.models.generate_content(
            model="gemini-1.5-flash",
            contents=prompt
        )
        return jsonify({"reply": response.text})

    except Exception as e:
        print("GEMINI DRAFT ERROR:", e)
        return jsonify({"reply": "⚠️ Failed to generate draft."}), 503
