import json
from pathlib import Path

source = Path("data/attack_mapping_review.json")
output = Path("data/accepted_attack_mapping_candidates.json")

accepted_pairs = {
    ("CVE-2021-21972", "T1190"),
    ("CVE-2021-44228", "T1190"),
    ("CVE-2022-26134", "T1190"),
    ("CVE-2022-30190", "T1105"),
    ("CVE-2022-30190", "T1204.002"),
    ("CVE-2023-23397", "T1078"),
    ("CVE-2023-34362", "T1136"),
    ("CVE-2023-34362", "T1082"),
    ("CVE-2023-34362", "T1190"),
    ("CVE-2024-21762", "T1190"),
    ("CVE-2023-27997", "T1190"),
    ("CVE-2020-1472", "T1068"),
    ("CVE-2023-20198", "T1136"),
    ("CVE-2023-20198", "T1190"),
    ("CVE-2023-22515", "T1136"),
    ("CVE-2023-22515", "T1190"),
    ("CVE-2022-22965", "T1059"),
    ("CVE-2022-22965", "T1190"),
}

data = json.loads(source.read_text(encoding="utf-8-sig"))
triples = data.get("triples")

if not isinstance(triples, list):
    raise SystemExit("Expected a list under the 'triples' key.")

accepted = [
    dict(row)
    for row in triples
    if (
        str(row.get("subject", "")).upper(),
        str(row.get("object", "")).upper(),
    ) in accepted_pairs
    and row.get("predicate") == "ASSOCIATED_WITH_TECHNIQUE"
]

for row in accepted:
    row["decision"] = "accept"
    row["status"] = "candidate_review_required"
    row["verification_note"] = (
        "Preliminary selection only. Verify the cited source and exact "
        "evidence span before treating this mapping as gold ground truth."
    )

found = {(r["subject"].upper(), r["object"].upper()) for r in accepted}
missing = sorted(accepted_pairs - found)

result = {
    "notice": (
        "Preliminarily accepted candidates; these are not automatically "
        "verified gold annotations."
    ),
    "count": len(accepted),
    "triples": accepted,
}

output.write_text(
    json.dumps(result, indent=2, ensure_ascii=False) + "\n",
    encoding="utf-8",
)

print(f"Created: {output}")
print(f"Records written: {len(accepted)}")
print(f"Unique accepted pairs found: {len(found)} of {len(accepted_pairs)}")

if missing:
    print("Pairs not found in the source file:")
    for cve, technique in missing:
        print(f"  {cve} -> {technique}")

print("Original files and Neo4j database were not modified.")
