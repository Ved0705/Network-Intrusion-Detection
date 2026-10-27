import os
import time
from pathlib import Path

from dotenv import load_dotenv
from litellm import completion

load_dotenv(Path(__file__).resolve().parents[1] / ".env")
model = os.getenv("PANDASAI_LLM_MODEL")
print("Model:", model)
start = time.time()
try:
    r = completion(model=model, messages=[{"role": "user", "content": "Reply with the single word OK"}], timeout=30)
    print("Reply:", r.choices[0].message.content.strip())
    print(f"Connection works ({time.time() - start:.1f} s)")
except Exception as exc:
    print(f"FAILED after {time.time() - start:.1f} s: {type(exc).__name__}: {str(exc)[:600]}")
