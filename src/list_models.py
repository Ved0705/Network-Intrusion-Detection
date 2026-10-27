import os
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

PROVIDERS = {
    "groq": ("GROQ_API_KEY", "https://api.groq.com/openai/v1/models", "bearer"),
    "openai": ("OPENAI_API_KEY", "https://api.openai.com/v1/models", "bearer"),
    "gemini": ("GEMINI_API_KEY", "https://generativelanguage.googleapis.com/v1beta/models", "query"),
}

for name, (env, url, auth) in PROVIDERS.items():
    key = os.getenv(env)
    if not key:
        continue
    try:
        if auth == "bearer":
            r = httpx.get(url, headers={"Authorization": f"Bearer {key}"}, timeout=20)
        else:
            r = httpx.get(url, params={"key": key, "pageSize": 200}, timeout=20)
        r.raise_for_status()
        data = r.json()
        if name == "gemini":
            ids = [m["name"].split("/", 1)[1] for m in data.get("models", [])
                   if "generateContent" in m.get("supportedGenerationMethods", [])]
        else:
            ids = [m["id"] for m in data.get("data", [])]
        print(f"\n{name.upper()} models available to your key (use as PANDASAI_LLM_MODEL={name}/<id>):")
        for i in sorted(ids):
            print(f"  {name}/{i}")
    except Exception as exc:
        print(f"\n{name.upper()}: could not list models ({type(exc).__name__}: {str(exc)[:200]})")
