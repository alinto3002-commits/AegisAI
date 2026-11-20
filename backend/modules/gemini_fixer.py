import os
import json
import urllib.request
import logging
import re
from typing import Optional

from backend.config import GEMINI_API_KEY

logger = logging.getLogger(__name__)

GEMINI_MODELS = [
    "gemini-3.5-flash-lite",
    "gemini-3.5-flash",
    "gemini-flash-latest",
    "gemini-flash-lite-latest",
    "gemini-3.8-flash",
]

def correct_code_line_with_gemini(faulty_line: str, context_lines: str = "", language: str = "python", error_msg: str = "") -> Optional[str]:
    api_key = os.getenv("GEMINI_API_KEY", "") or GEMINI_API_KEY
    if not api_key:
        return None

    prompt = (
        f"You are an expert compiler and software engineer fixing code syntax and spelling errors.\n"
        f"Language: {language}\n"
        f"Reported issue: {error_msg}\n"
        f"Surrounding code context:\n```\n{context_lines[:600]}\n```\n\n"
        f"Faulty code line with spelling/syntax error:\n{faulty_line}\n\n"
        f"TASK: Fix the spelling mistake or syntax error on this exact code line.\n"
        f"RULES:\n"
        f"- Return ONLY the single corrected code line.\n"
        f"- Do NOT add any comments (# or //).\n"
        f"- Do NOT wrap in markdown code blocks.\n"
        f"- Do NOT return explanations.\n"
        f"- Preserve exact leading indentation."
    )

    for model in GEMINI_MODELS:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
            payload = json.dumps({
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.1, "maxOutputTokens": 150}
            }).encode("utf-8")

            req = urllib.request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=4) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode("utf-8"))
                    candidates = data.get("candidates", [])
                    if candidates:
                        parts = candidates[0].get("content", {}).get("parts", [])
                        if parts:
                            res = parts[0].get("text", "").strip()
                            if res.startswith("```"):
                                res = re.sub(r"^```[a-zA-Z]*\n?", "", res)
                                res = re.sub(r"```$", "", res).strip()
                            clean_lines = [l for l in res.splitlines() if not l.strip().startswith(("#", "//", "/*", "*"))]
                            if clean_lines:
                                return clean_lines[0]
        except Exception as e:
            logger.debug(f"Gemini correction attempt with {model} failed: {e}")
            continue

    return None
