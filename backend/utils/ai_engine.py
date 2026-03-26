from google import genai
from config import GEMINI_API_KEY

client = genai.Client(api_key=GEMINI_API_KEY)

def get_ai_response(detector, input_data, status):
    prompt = f"""
You are a cybersecurity expert.

Detector: {detector}
Input: {input_data}
Result: {status}

Explain clearly and give 3 safety tips.
"""

    try:
        response = client.models.generate_content(
            model="gemini-1.5-flash",
            contents=prompt
        )

        return {
            "explanation": response.text,
            "tips": []
        }

    except Exception as e:
        print("AI ERROR:", e)
        return {
            "explanation": "AI explanation unavailable.",
            "tips": [
                "Do not share sensitive information",
                "Verify sources before action",
                "Report suspicious activity"
            ]
        }
