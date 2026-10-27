import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import analysis as A  # noqa: E402
import pandasai_analysis as P  # noqa: E402
from data_loader import DatasetMissingError, load_dataset  # noqa: E402

st.set_page_config(page_title="Network Traffic Q&A", page_icon="🛡️", layout="wide")


@st.cache_data(show_spinner="Loading dataset...")
def get_data(source: str) -> pd.DataFrame:
    return load_dataset(source)[0]


def show_answer(result: dict):
    if "error" in result:
        st.error(result["error"])
        if result.get("pandas"):
            st.info(f"Pandas answer instead: **{result['pandas']}**")
        return
    st.caption(f"Answered by {result['source']}")
    answer = result["answer"]
    if isinstance(answer, pd.DataFrame):
        st.dataframe(answer, use_container_width=True)
    elif isinstance(answer, str) and answer.lower().endswith(".png") and Path(answer).exists():
        st.image(answer)
    else:
        st.markdown(f"### {answer}")
    check = result.get("pandas_check", "")
    if check.startswith("MATCH"):
        st.success(f"Pandas check: {check}")
    elif check.startswith("MISMATCH"):
        st.warning(f"Pandas check: {check}")
    elif check:
        st.caption(f"Pandas check: {check}")
    if result.get("sql"):
        with st.expander("SQL that PandasAI ran on your computer"):
            for q in result["sql"]:
                st.code(q, language="sql")


with st.sidebar:
    st.title("🛡️ Network Traffic Q&A")
    st.caption("NSL-KDD dataset · PandasAI")
    source = st.radio("Dataset", ["train", "test"], horizontal=True)
    status = P.configuration_status()
    if status["ready"]:
        st.success(f"PandasAI ready\n\nModel: `{status['model']}`")
    else:
        st.error("PandasAI not ready")
        for p in status["problems"]:
            st.write("•", p)
    st.info(P.DATA_SHARING_NOTE)
    if st.button("Clear conversation"):
        st.session_state.messages = []

try:
    df = get_data(source)
except DatasetMissingError as exc:
    st.error(str(exc))
    st.stop()

o = A.overview(df)
c1, c2, c3, c4 = st.columns(4)
c1.metric("Connections", f"{o['total_connections']:,}")
c2.metric("Normal", f"{o['normal_connections']:,}")
c3.metric("Attacks", f"{o['attack_connections']:,}")
c4.metric("Attack %", f"{o['attack_percentage']}%")

st.session_state.setdefault("messages", [])

st.write("**Try a question:**")
cols = st.columns(3)
clicked = None
for i, q in enumerate(P.EXAMPLE_QUESTIONS):
    if cols[i % 3].button(q, key=f"ex{i}", use_container_width=True):
        clicked = q

for m in st.session_state.messages:
    with st.chat_message(m["role"]):
        if m["role"] == "user":
            st.write(m["content"])
        else:
            show_answer(m["content"])

question = st.chat_input("Ask a question about the network traffic data") or clicked

if question:
    st.session_state.messages.append({"role": "user", "content": f"[{source}] {question}"})
    with st.chat_message("user"):
        st.write(f"[{source}] {question}")
    with st.chat_message("assistant"):
        if not status["ready"]:
            ref = P.pandas_reference(question, df)
            result = {"source": "Pandas", "error": "PandasAI is not configured.",
                      "pandas": ref["value"] if ref else None}
        else:
            with st.spinner("PandasAI is writing and running a query..."):
                try:
                    result = P.ask(question, df)
                except Exception as exc:
                    result = {"source": "PandasAI", "error": f"{type(exc).__name__}: {exc}"}
            if "error" in result:
                ref = P.pandas_reference(question, df)
                result["pandas"] = ref["value"] if ref else None
        show_answer(result)
    st.session_state.messages.append({"role": "assistant", "content": result})
