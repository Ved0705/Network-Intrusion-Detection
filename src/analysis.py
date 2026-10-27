import pandas as pd

from data_loader import NUMERIC_COLUMNS


def pct(part, whole):
    return round(100 * part / whole, 2) if whole else 0.0


def overview(df: pd.DataFrame) -> dict:
    total = len(df)
    attacks = int(df["is_attack"].sum())
    return {
        "dataset_source": df["dataset_source"].iloc[0] if total else None,
        "total_connections": total,
        "normal_connections": total - attacks,
        "attack_connections": attacks,
        "attack_percentage": pct(attacks, total),
        "distinct_attack_labels": int(df.loc[df["is_attack"] == 1, "label"].nunique()),
        "most_frequent_protocol": df["protocol_type"].mode().iloc[0] if total else None,
    }


def normal_vs_attack(df: pd.DataFrame) -> pd.DataFrame:
    out = df["traffic_type"].value_counts().rename_axis("traffic_type").reset_index(name="connections")
    out["percentage_of_total"] = out["connections"].map(lambda v: pct(v, len(df)))
    return out


def attack_distribution(df: pd.DataFrame) -> pd.DataFrame:
    attacks = df[df["is_attack"] == 1]
    out = (attacks.groupby(["label", "attack_family"]).size().reset_index(name="connections")
           .sort_values("connections", ascending=False))
    out["percentage_of_attacks"] = out["connections"].map(lambda v: pct(v, len(attacks)))
    out["percentage_of_total"] = out["connections"].map(lambda v: pct(v, len(df)))
    return out.rename(columns={"label": "attack_label"}).reset_index(drop=True)


def attack_family_summary(df: pd.DataFrame) -> pd.DataFrame:
    attacks = df[df["is_attack"] == 1]
    out = attacks["attack_family"].value_counts().rename_axis("attack_family").reset_index(name="connections")
    out["distinct_labels"] = out["attack_family"].map(attacks.groupby("attack_family")["label"].nunique())
    out["percentage_of_attacks"] = out["connections"].map(lambda v: pct(v, len(attacks)))
    out["percentage_of_total"] = out["connections"].map(lambda v: pct(v, len(df)))
    return out


def category_summary(df: pd.DataFrame, column: str) -> pd.DataFrame:
    g = df.groupby(column).agg(total_connections=("is_attack", "size"), attack_connections=("is_attack", "sum"))
    g["normal_connections"] = g["total_connections"] - g["attack_connections"]
    g["percentage_of_total"] = g["total_connections"].map(lambda v: pct(v, len(df)))
    g["attack_percentage_within"] = [pct(a, t) for a, t in zip(g["attack_connections"], g["total_connections"])]
    g["percentage_of_all_attacks"] = g["attack_connections"].map(lambda v: pct(v, df["is_attack"].sum()))
    cols = ["total_connections", "normal_connections", "attack_connections", "percentage_of_total",
            "attack_percentage_within", "percentage_of_all_attacks"]
    return g[cols].sort_values("total_connections", ascending=False).reset_index()


def attack_breakdown(df: pd.DataFrame, column: str) -> pd.DataFrame:
    attacks = df[df["is_attack"] == 1]
    out = attacks.groupby([column, "attack_family"]).size().reset_index(name="attack_connections")
    out["percentage_of_attacks"] = out["attack_connections"].map(lambda v: pct(v, len(attacks)))
    return out.sort_values("attack_connections", ascending=False).reset_index(drop=True)


def numeric_feature_summary(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for traffic, part in [("All", df), ("Normal", df[df["is_attack"] == 0]), ("Attack", df[df["is_attack"] == 1])]:
        for col in NUMERIC_COLUMNS:
            s = part[col]
            if s.empty:
                continue
            rows.append({"traffic_type": traffic, "feature": col, "count": int(s.count()),
                         "mean": round(s.mean(), 4), "std": round(s.std(), 4), "min": s.min(),
                         "q25": s.quantile(0.25), "median": s.median(), "q75": s.quantile(0.75),
                         "max": s.max(), "zero_percentage": pct((s == 0).sum(), len(s))})
    return pd.DataFrame(rows)


def compare_normal_attack(df: pd.DataFrame, features=("duration", "src_bytes", "dst_bytes", "count",
                                                       "srv_count", "serror_rate", "same_srv_rate",
                                                       "dst_host_count")) -> pd.DataFrame:
    return df.groupby("traffic_type")[list(features)].agg(["mean", "median"]).round(3).T


def data_quality(df_raw: pd.DataFrame) -> pd.DataFrame:
    return pd.DataFrame({"missing_values": df_raw.isna().sum(), "dtype": df_raw.dtypes.astype(str)})
