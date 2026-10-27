import json
from pathlib import Path

import pandas as pd

PROJECT_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_DIR / "data"
FAMILY_FILE = Path(__file__).with_name("attack_families.json")

FEATURE_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]
CATEGORICAL_COLUMNS = ["protocol_type", "service", "flag"]
NUMERIC_COLUMNS = [c for c in FEATURE_COLUMNS if c not in CATEGORICAL_COLUMNS]

DATASET_FILES = {"train": "KDDTrain+.txt", "test": "KDDTest+.txt"}


class DatasetMissingError(FileNotFoundError):
    pass


def load_family_mapping(path: Path = FAMILY_FILE) -> dict:
    families = json.loads(Path(path).read_text(encoding="utf-8"))
    return {label: family for family, labels in families.items() for label in labels}


def read_nslkdd(path: Path) -> pd.DataFrame:
    path = Path(path)
    if not path.exists():
        raise DatasetMissingError(
            f"{path.name} was not found in {path.parent}. Place the NSL-KDD file there (see data/README.md).")
    first_line = path.open(encoding="utf-8").readline().strip()
    first_values = [v.strip().lower() for v in first_line.split(",")]
    if "protocol_type" in first_values:
        df = pd.read_csv(path)
        df.columns = [c.strip().lower() for c in df.columns]
        return df
    if len(first_values) == 43:
        names = FEATURE_COLUMNS + ["label", "difficulty_level"]
    elif len(first_values) == 42:
        names = FEATURE_COLUMNS + ["label"]
    else:
        raise ValueError(f"{path.name} has {len(first_values)} columns; NSL-KDD files have 42 or 43.")
    return pd.read_csv(path, header=None, names=names)


def clean_dataset(raw: pd.DataFrame, source: str, family_map: dict | None = None) -> tuple[pd.DataFrame, dict]:
    family_map = family_map if family_map is not None else load_family_mapping()
    df = raw.copy()
    for col in NUMERIC_COLUMNS + (["difficulty_level"] if "difficulty_level" in df.columns else []):
        df[col] = pd.to_numeric(df[col], errors="coerce")
    for col in CATEGORICAL_COLUMNS:
        df[col] = df[col].astype("string").str.strip()

    df["original_label"] = df["label"]
    df["label"] = df["label"].astype("string").str.strip().str.lower().str.rstrip(".")

    required = FEATURE_COLUMNS + ["label"]
    bad_rows = df[required].isna().any(axis=1)
    report = {
        "dataset_source": source,
        "rows_in_file": len(raw),
        "missing_values_in_file": int(raw.isna().sum().sum()),
        "duplicate_rows_in_file": int(raw.duplicated().sum()),
        "rows_removed_missing_or_invalid": int(bad_rows.sum()),
        "has_difficulty_level": "difficulty_level" in raw.columns,
    }
    df = df[~bad_rows].copy()

    df["traffic_type"] = df["label"].map(lambda x: "Normal" if x == "normal" else "Attack")
    df["is_attack"] = (df["traffic_type"] == "Attack").astype(int)
    df["attack_family"] = df["label"].map(
        lambda x: "Normal" if x == "normal" else family_map.get(x, "Unknown"))
    df["dataset_source"] = source
    df = df.drop(columns=["original_label"]) if (df["original_label"] == df["label"]).all() else df

    report["rows_after_cleaning"] = len(df)
    report["unknown_attack_labels"] = sorted(df.loc[df["attack_family"] == "Unknown", "label"].unique().tolist())
    return df.reset_index(drop=True), report


def load_dataset(source: str = "train", data_dir: Path = DATA_DIR) -> tuple[pd.DataFrame, dict]:
    if source not in DATASET_FILES:
        raise ValueError("source must be 'train' or 'test'")
    raw = read_nslkdd(Path(data_dir) / DATASET_FILES[source])
    return clean_dataset(raw, source)
