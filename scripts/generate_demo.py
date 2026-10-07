import argparse
import csv
import json
from pathlib import Path

from traceguard.demo import generate_demo


def main():
    parser = argparse.ArgumentParser(description="Generate reproducible small synthetic source files")
    parser.add_argument("--seed", type=int, default=17)
    parser.add_argument("--variant", choices=["positive", "benign", "missing-transfer"], default="positive")
    parser.add_argument("--output", type=Path, default=Path("runtime/demo"))
    args = parser.parse_args()
    files, resources = generate_demo(args.seed, args.variant)
    args.output.mkdir(parents=True, exist_ok=True)
    for family, rows in files.items():
        (args.output / f"{family}.jsonl").write_text("\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n", encoding="utf-8")
        with (args.output / f"{family}.csv").open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=sorted({key for row in rows for key in row}))
            writer.writeheader()
            writer.writerows(rows)
    (args.output / "trusted_resources.json").write_text(json.dumps(resources, indent=2), encoding="utf-8")
    print(f"Wrote {sum(map(len, files.values()))} synthetic records to {args.output.resolve()}")


if __name__ == "__main__":
    main()
