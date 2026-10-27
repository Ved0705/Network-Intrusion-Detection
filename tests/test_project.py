import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import analysis as A  # noqa: E402
import pandasai_analysis as P  # noqa: E402
from data_loader import FEATURE_COLUMNS, DatasetMissingError, clean_dataset, load_dataset, read_nslkdd  # noqa: E402
from export_data import build_exports, write_exports  # noqa: E402


def row(label, protocol="tcp", service="http", flag="SF", duration=0, src=100, difficulty=True):
    values = [str(duration), protocol, service, flag, str(src), "50"] + ["0"] * 35 + [label]
    return ",".join(values + (["20"] if difficulty else []))


ROWS = [row("normal", duration=2), row("normal", "udp", "domain_u", duration=4), row("neptune", flag="S0"),
        row("neptune", flag="S0"), row("smurf", "icmp", "ecr_i"), row("satan", flag="REJ"),
        row("guess_passwd", service="telnet"), row("rootkit", service="telnet"), row("brand_new_attack")]


@pytest.fixture
def data_dir(tmp_path):
    (tmp_path / "KDDTrain+.txt").write_text("\n".join(ROWS) + "\n")
    (tmp_path / "KDDTest+.txt").write_text("\n".join(r.rsplit(",", 1)[0] for r in ROWS[:4]) + "\n")
    return tmp_path


@pytest.fixture
def train(data_dir):
    return load_dataset("train", data_dir)[0]


def test_headerless_columns_and_count(data_dir):
    raw = read_nslkdd(data_dir / "KDDTrain+.txt")
    assert list(raw.columns) == FEATURE_COLUMNS + ["label", "difficulty_level"]
    assert len(raw) == len(ROWS)


def test_missing_difficulty_column(data_dir):
    df, report = load_dataset("test", data_dir)
    assert "difficulty_level" not in df.columns and report["has_difficulty_level"] is False
    assert len(df) == 4


def test_normal_vs_attack(train):
    o = A.overview(train)
    assert (o["total_connections"], o["normal_connections"], o["attack_connections"]) == (9, 2, 7)
    assert o["attack_percentage"] == 77.78


def test_family_mapping_and_unknown(data_dir):
    df, report = load_dataset("train", data_dir)
    fam = dict(zip(df["label"], df["attack_family"]))
    assert fam["neptune"] == "DoS" and fam["smurf"] == "DoS" and fam["satan"] == "Probe"
    assert fam["guess_passwd"] == "R2L" and fam["rootkit"] == "U2R" and fam["normal"] == "Normal"
    assert fam["brand_new_attack"] == "Unknown"
    assert report["unknown_attack_labels"] == ["brand_new_attack"]


def test_label_preserved_when_normalised():
    raw = read_csv_rows([row("Neptune.")])
    df, _ = clean_dataset(raw, "x", {"neptune": "DoS"})
    assert df.loc[0, "label"] == "neptune" and df.loc[0, "original_label"] == "Neptune."


def read_csv_rows(rows):
    from io import StringIO
    return pd.read_csv(StringIO("\n".join(rows)), header=None, names=FEATURE_COLUMNS + ["label", "difficulty_level"])


def test_missing_values_removed_and_reported():
    bad = row("normal").split(",")
    bad[4] = ""
    df, report = clean_dataset(read_csv_rows([",".join(bad)] + ROWS), "x", {})
    assert report["rows_removed_missing_or_invalid"] == 1 and report["missing_values_in_file"] == 1
    assert len(df) == len(ROWS)


def test_aggregations(train):
    proto = A.category_summary(train, "protocol_type").set_index("protocol_type")
    assert proto.loc["icmp", "attack_percentage_within"] == 100.0
    assert proto["total_connections"].sum() == 9
    fam = A.attack_family_summary(train).set_index("attack_family")
    assert fam.loc["DoS", "connections"] == 3 and fam["connections"].sum() == 7
    dist = A.attack_distribution(train)
    assert dist.iloc[0]["attack_label"] == "neptune" and dist["connections"].sum() == 7


def test_exports(data_dir, tmp_path):
    datasets = {s: load_dataset(s, data_dir)[0] for s in ("train", "test")}
    paths = write_exports(build_exports(datasets), tmp_path / "out")
    names = {p.name for p in paths}
    assert {"cleaned_dataset.csv", "attack_distribution.csv", "attack_family_summary.csv", "protocol_summary.csv",
            "service_summary.csv", "normal_vs_attack.csv", "protocol_attack_summary.csv",
            "service_attack_summary.csv", "flag_summary.csv", "numeric_feature_summary.csv"} <= names
    nva = pd.read_csv(tmp_path / "out" / "normal_vs_attack.csv")
    assert list(nva.columns) == ["dataset_source", "traffic_type", "connections", "percentage_of_total"]
    train_rows = nva[nva.dataset_source == "train"].set_index("traffic_type")
    assert train_rows.loc["Attack", "connections"] == 7
    cleaned = pd.read_csv(tmp_path / "out" / "cleaned_dataset.csv")
    assert len(cleaned) == 13 and set(cleaned.dataset_source) == {"train", "test"}


def test_missing_file_message(tmp_path):
    with pytest.raises(DatasetMissingError, match="KDDTrain"):
        load_dataset("train", tmp_path)


def test_pandas_reference_and_check(train):
    ref = P.pandas_reference("How many DoS attacks are present?", train)
    assert ref["value"] == 3
    assert P.check_against_pandas("There are 3 DoS attacks", ref).startswith("MATCH")
    assert P.check_against_pandas(5, ref).startswith("MISMATCH")
    assert P.pandas_reference("Which attack family is most frequent?", train)["value"] == "DoS"


def test_missing_credentials(monkeypatch, train):
    monkeypatch.setenv("PANDASAI_LLM_MODEL", "")
    with pytest.raises(P.PandasAIUnavailable):
        P.ask("How many DoS attacks are present?", train)


@pytest.mark.skipif(not P.configuration_status()["installed"], reason="PandasAI not installed")
@pytest.mark.parametrize("code,ok", [
    ("df = execute_sql_query(\"SELECT COUNT(*) AS n FROM connections WHERE attack_family = 'DoS'\")\n"
     "result = {'type': 'number', 'value': int(df['n'][0])}", True),
    ("result = {'type': 'number', 'value': 999}", False),
    ("df = execute_sql_query(\"SELECT * FROM read_csv('C:/secret.csv')\")\nresult = {'type': 'dataframe', 'value': df}", False),
])
def test_pandasai_pipeline_with_stub_llm(monkeypatch, train, code, ok):
    from pandasai.llm.base import LLM

    class Stub(LLM):
        type = "stub"

        def call(self, instruction, context=None):
            return f"```python\n{code}\n```"

    monkeypatch.setenv("PANDASAI_LLM_MODEL", "gpt-test")
    monkeypatch.setenv("OPENAI_API_KEY", "x")
    monkeypatch.setattr("pandasai_litellm.LiteLLM", lambda **kw: Stub())
    result = P.ask("How many DoS attacks are present?", train)
    if ok:
        assert result["answer"] == 3 and result["pandas_check"].startswith("MATCH")
    else:
        assert "error" in result
