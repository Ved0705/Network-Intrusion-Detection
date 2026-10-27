import os
import re
import sys

import pandas as pd

import analysis as A
from data_loader import PROJECT_DIR, load_dataset
from safety import UnsafeCodeError, UnsafeSQLError, restricted_builtins, validate_code, validate_sql

try:
    from dotenv import load_dotenv
    load_dotenv(PROJECT_DIR / ".env")
except ImportError:
    pass

TABLE_NAME = "connections"

EXAMPLE_QUESTIONS = [
    "How many DoS attacks are present?",
    "Which protocol occurs most frequently?",
    "What percentage of connections are attacks?",
    "Show the distribution of attack types.",
    "Which service has the highest number of attacks?",
    "Compare normal and attack connections.",
    "What is the average duration for normal and attack connections?",
    "Summarize the dataset.",
    "Which attack family is most frequent?",
]

DATA_SHARING_NOTE = (
    "PandasAI sends your question, the column names and types, the table size and the first 5 rows of the "
    "dataset to the configured LLM provider so it can write code. The full dataset stays on your computer; "
    "the generated SQL runs locally."
)

KEY_FOR_PREFIX = [("anthropic/", "ANTHROPIC_API_KEY"), ("gemini/", "GEMINI_API_KEY"), ("groq/", "GROQ_API_KEY"),
                  ("ollama/", None), ("openai/", "OPENAI_API_KEY"), ("gpt", "OPENAI_API_KEY"),
                  ("o3", "OPENAI_API_KEY"), ("o4", "OPENAI_API_KEY")]


class PandasAIUnavailable(RuntimeError):
    pass


def configuration_status() -> dict:
    model = os.getenv("PANDASAI_LLM_MODEL", "").strip()
    key_env = next((k for p, k in KEY_FOR_PREFIX if model.lower().startswith(p)), "OPENAI_API_KEY")
    try:
        import pandasai  # noqa: F401
        installed = True
    except Exception:
        installed = False
    problems = []
    if not installed:
        problems.append("PandasAI is not installed (it needs Python 3.10 or 3.11; see README).")
    if not model:
        problems.append("PANDASAI_LLM_MODEL is not set in .env.")
    elif key_env and not os.getenv(key_env):
        problems.append(f"{key_env} is not set in .env.")
    return {"installed": installed, "model": model or None, "key_env": key_env, "ready": not problems,
            "problems": problems}


def pandas_reference(question: str, df: pd.DataFrame) -> dict | None:
    q = question.lower()
    attacks = df[df["is_attack"] == 1]
    for fam in ["DoS", "Probe", "R2L", "U2R"]:
        if re.search(rf"\b{fam.lower()}\b", q):
            return {"description": f"{fam} records", "value": int((df["attack_family"] == fam).sum())}
    if "percent" in q and "attack" in q:
        return {"description": "attack percentage", "value": A.pct(len(attacks), len(df))}
    if "family" in q and ("most" in q or "frequent" in q):
        top = attacks["attack_family"].value_counts()
        return {"description": "most frequent attack family", "value": top.index[0], "count": int(top.iloc[0])}
    if "service" in q and "attack" in q:
        top = attacks["service"].value_counts()
        return {"description": "service with most attacks", "value": top.index[0], "count": int(top.iloc[0])}
    if "protocol" in q:
        top = df["protocol_type"].value_counts()
        return {"description": "most frequent protocol", "value": top.index[0], "count": int(top.iloc[0])}
    if "duration" in q:
        means = df.groupby("traffic_type")["duration"].mean().round(4)
        return {"description": "mean duration by traffic type", "value": means.to_dict()}
    if "how many" in q and ("connection" in q or "record" in q):
        return {"description": "total connections", "value": len(df)}
    return None


def _values_in(answer) -> list:
    if isinstance(answer, (int, float)):
        return [float(answer)]
    if isinstance(answer, pd.DataFrame):
        return [float(v) for v in answer.select_dtypes("number").to_numpy().ravel()]
    return [float(x.replace(",", "")) for x in re.findall(r"-?\d[\d,]*\.?\d*", str(answer))]


def check_against_pandas(answer, reference: dict | None) -> str:
    if reference is None:
        return "not checked (no matching Pandas calculation for this question)"
    expected = reference["value"]
    if isinstance(expected, (int, float)):
        found = _values_in(answer)
        ok = any(abs(v - expected) <= max(0.01, abs(expected) * 0.001) for v in found)
        return f"{'MATCH' if ok else 'MISMATCH'}: Pandas gives {reference['description']} = {expected}"
    if isinstance(expected, str):
        text = answer.to_string() if isinstance(answer, pd.DataFrame) else str(answer)
        ok = expected.lower() in text.lower()
        return f"{'MATCH' if ok else 'MISMATCH'}: Pandas gives {reference['description']} = {expected}"
    return f"compare manually: Pandas gives {reference['description']} = {expected}"


def _make_sandbox(table: pd.DataFrame):
    import duckdb
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    from pandasai.sandbox import Sandbox

    class RestrictedSandbox(Sandbox):
        def __init__(self):
            super().__init__()
            self.queries = []

        def start(self):
            self._started = True

        def stop(self):
            self._started = False

        def transfer_file(self, csv_data, filename="file.csv"):
            raise UnsafeCodeError("File transfer is disabled")

        def run_sql(self, query):
            safe = validate_sql(query)
            con = duckdb.connect(":memory:", config={"enable_external_access": False})
            try:
                con.register(TABLE_NAME, table)
                out = con.execute(safe).df()
            finally:
                con.close()
            self.queries.append(safe)
            return out

        def _exec_code(self, code, environment):
            validate_code(code)
            env = {"__builtins__": restricted_builtins(), "pd": pd, "np": np, "plt": plt,
                   "execute_sql_query": self.run_sql}
            exec(compile(code, "<pandasai>", "exec"), env)
            return env["result"]

    return RestrictedSandbox()


def ask(question: str, df: pd.DataFrame) -> dict:
    status = configuration_status()
    if not status["ready"]:
        raise PandasAIUnavailable(" ".join(status["problems"]))
    if not question.strip() or len(question) > 500:
        raise ValueError("Questions must be between 1 and 500 characters.")

    import pandasai as pai
    from pandasai import Agent
    from pandasai_litellm import LiteLLM

    table = df.copy()
    for col in table.select_dtypes(include=["string", "category"]).columns:
        table[col] = table[col].astype(object)
    pai.config.set({"llm": LiteLLM(model=status["model"], timeout=45, num_retries=0), "save_logs": False, "max_retries": 1})
    sandbox = _make_sandbox(table)
    agent = Agent(pai.DataFrame(table, _table_name=TABLE_NAME,
                                description="NSL-KDD historical network connection records"), sandbox=sandbox)
    try:
        response = agent.chat(question)
    except (UnsafeCodeError, UnsafeSQLError) as exc:
        return {"source": "PandasAI", "error": f"Generated code was blocked: {exc}"}
    except Exception as exc:
        return {"source": "PandasAI", "error": f"PandasAI or the LLM provider failed: {type(exc).__name__}: {exc}"}

    if getattr(response, "type", None) == "error":
        return {"source": "PandasAI", "error": "PandasAI could not produce a valid answer. Try rephrasing."}
    if not sandbox.queries:
        return {"source": "PandasAI", "error": "Answer rejected: it was not computed from the dataset."}
    value = response.value
    return {
        "source": f"PandasAI ({status['model']})",
        "answer": value,
        "sql": sandbox.queries,
        "pandas_check": check_against_pandas(value, pandas_reference(question, df)),
    }


def main():
    source = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] in ("train", "test") else "train"
    df, _ = load_dataset(source)
    status = configuration_status()
    print(f"Dataset: {source} ({len(df):,} records)")
    if not status["ready"]:
        print("PandasAI is not ready:", " ".join(status["problems"]))
        print("Deterministic Pandas results for the example questions:")
        for q in EXAMPLE_QUESTIONS:
            ref = pandas_reference(q, df)
            if ref:
                print(f"  [Pandas] {q} -> {ref['value']}")
        return
    print(DATA_SHARING_NOTE)
    print("Type a question, or press Enter to quit.")
    while True:
        q = input("\nQuestion: ").strip()
        if not q:
            break
        print("Working... (asking the LLM and running the query locally, can take up to a minute)", flush=True)
        result = ask(q, df)
        if "error" in result:
            print(f"[{result['source']}] {result['error']}")
            continue
        print(f"[{result['source']}]\n{result['answer']}")
        print(f"SQL run locally: {result['sql']}")
        print(f"Pandas check: {result['pandas_check']}")


if __name__ == "__main__":
    main()
