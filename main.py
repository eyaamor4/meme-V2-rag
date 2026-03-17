import argparse
import json
import os

from parser import extract_findings, extract_metadata
from llm import analyze_full


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input", help="Path to scan JSON file")
    ap.add_argument(
        "--top",
        type=int,
        default=0,
        help="Number of findings to detail (section B). Use 0 to include ALL findings.",
    )
    args = ap.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    metadata = extract_metadata(data)
    findings = extract_findings(data)

    report = analyze_full(findings, metadata, top_n=args.top)

    # créer dossier reports
    os.makedirs("reports", exist_ok=True)

    # récupérer le nom du fichier json sans extension
    base_name = os.path.splitext(os.path.basename(args.input))[0]

    # créer le fichier rapport avec le même nom
    report_path = os.path.join("reports", base_name + ".md")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"Rapport enregistré dans : {report_path}")


if __name__ == "__main__":
    main()