
import time
from graphrag_engine import answer_question

TESTS = [
    {
        "name": "Exact CVE lookup",
        "question": (
            "What is CVE-2026-21428, what is its CVSS score "
            "and severity, and which versions of cpp-httplib are affected?"
        ),
        "expected": ["CVE-2026-21428", "7.7", "HIGH", "0.30.0"],
    },
    {
        "name": "Product vulnerability retrieval",
        "question": (
            "What vulnerabilities affect cpp-httplib? List each CVE ID, "
            "CVSS score, severity, and affected version range."
        ),
        "expected": ["CVE-2026-21428", "CVE-2026-45372", "0.30.0", "0.44.0"],
        "minimum_citations": 13,
    },
    {
        "name": "Severity aggregation",
        "question": (
            "For cpp-httplib, how many vulnerabilities are HIGH, MEDIUM, "
            "and CRITICAL? Give the count for each severity and the total."
        ),
        "expected": ["HIGH: 8", "MEDIUM: 4", "CRITICAL: 1", "13 vulnerabilities"],
        "minimum_citations": 13,
    },
    {
        "name": "Highest-severity vulnerability",
        "question": (
            "For cpp-httplib, identify the most severe vulnerability, "
            "give its CVE ID and CVSS score, explain what it does, "
            "and state the affected version range."
        ),
        "expected": ["CVE-2026-45372", "9.9", "CRITICAL", "0.44.0"],
    },
]

def main():
    passed = 0
    total_latency_ms = 0

    for test in TESTS:
        print(f"\nTEST: {test['name']}")
        started = time.perf_counter()

        try:
            result = answer_question(test["question"])
            latency_ms = (time.perf_counter() - started) * 1000
            total_latency_ms += latency_ms

            answer = result.get("answer", "")
            citations = result.get("citations", [])
            missing = [
                item for item in test["expected"]
                if item.lower() not in answer.lower()
            ]

            minimum = test.get("minimum_citations", 1)
            citation_ok = len(citations) >= minimum
            success = not missing and citation_ok

            if success:
                passed += 1
                print("RESULT: PASS")
            else:
                print("RESULT: FAIL")
                if missing:
                    print("Missing expected text:", missing)
                if not citation_ok:
                    print(
                        f"Expected at least {minimum} citations; "
                        f"got {len(citations)}"
                    )

            print(f"Latency: {latency_ms:.2f} ms")
            print(f"Citations: {len(citations)}")
            print(f"Answer: {answer}")

        except Exception as exc:
            print("RESULT: ERROR")
            print(f"{type(exc).__name__}: {exc}")

    print(f"\nSUMMARY: {passed}/{len(TESTS)} tests passed")
    print(f"Average latency: {total_latency_ms / len(TESTS):.2f} ms")

if __name__ == "__main__":
    main()
