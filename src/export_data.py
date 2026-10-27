import argparse
from pathlib import Path

import pandas as pd

import analysis as A
from data_loader import PROJECT_DIR, DatasetMissingError, load_dataset

EXPORT_DIR = PROJECT_DIR / "exports"


def build_exports(datasets: dict) -> dict:
    def per_source(fn, *args):
        frames = []
        for source, df in datasets.items():
            part = fn(df, *args)
            part.insert(0, "dataset_source", source)
            frames.append(part)
        return pd.concat(frames, ignore_index=True)

    return {
        "cleaned_dataset.csv": pd.concat(datasets.values(), ignore_index=True),
        "normal_vs_attack.csv": per_source(A.normal_vs_attack),
        "attack_distribution.csv": per_source(A.attack_distribution),
        "attack_family_summary.csv": per_source(A.attack_family_summary),
        "protocol_summary.csv": per_source(A.category_summary, "protocol_type"),
        "service_summary.csv": per_source(A.category_summary, "service"),
        "flag_summary.csv": per_source(A.category_summary, "flag"),
        "protocol_attack_summary.csv": per_source(A.attack_breakdown, "protocol_type"),
        "service_attack_summary.csv": per_source(A.attack_breakdown, "service"),
        "numeric_feature_summary.csv": per_source(A.numeric_feature_summary),
    }


def write_exports(exports: dict, out_dir: Path = EXPORT_DIR) -> list[Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for name, frame in exports.items():
        path = out_dir / name
        frame.to_csv(path, index=False, encoding="utf-8")
        paths.append(path)
    return paths


def main():
    parser = argparse.ArgumentParser(description="Generate Power BI CSV exports from NSL-KDD")
    parser.add_argument("--sources", nargs="+", default=["train", "test"], choices=["train", "test"])
    args = parser.parse_args()

    datasets, reports = {}, []
    for source in args.sources:
        try:
            df, report = load_dataset(source)
        except DatasetMissingError as exc:
            print(f"Skipping {source}: {exc}")
            continue
        datasets[source] = df
        reports.append(report)
        o = A.overview(df)
        print(f"[{source}] {o['total_connections']:,} connections | {o['normal_connections']:,} normal | "
              f"{o['attack_connections']:,} attacks ({o['attack_percentage']}%) | "
              f"{o['distinct_attack_labels']} attack labels")
    if not datasets:
        raise SystemExit("No dataset files found. See data/README.md.")

    paths = write_exports(build_exports(datasets))
    pd.DataFrame(reports).to_csv(EXPORT_DIR / "data_quality_report.csv", index=False)
    print(f"\nWrote {len(paths) + 1} files to {EXPORT_DIR}:")
    for p in paths + [EXPORT_DIR / "data_quality_report.csv"]:
        print(f"  {p.name}")


if __name__ == "__main__":
    main()
