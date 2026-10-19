import os
import re
import time

import ollama
from neo4j import GraphDatabase


STOPWORDS = {
    "what", "which", "when", "where", "who", "why", "how",
    "does", "did", "are", "is", "was", "were", "the", "a",
    "an", "and", "or", "of", "for", "to", "in", "on", "with",
    "about", "tell", "me", "show", "find", "list", "explain",
    "please", "can", "could", "would", "this", "that", "from",
}

def extract_fixed_version(description: str | None) -> str | None:
    """Return only an explicitly stated fixed version."""
    if not description:
        return None

    patterns = [
        r"\bfixed\s+in\s+(?:version\s+)?v?([0-9]+(?:[.][0-9]+)+)\b",
        r"\bpatched\s+in\s+(?:version\s+)?v?([0-9]+(?:[.][0-9]+)+)\b",
        r"\bversion\s+v?([0-9]+(?:[.][0-9]+)+)\s+fixes\b",
        r"\bversion\s+v?([0-9]+(?:[.][0-9]+)+)\s+fixes\s+the\s+issue\b",
    ]

    for pattern in patterns:
        match = re.search(pattern, description, re.IGNORECASE)
        if match:
            return match.group(1)

    return None



def retrieve_graph_evidence(question: str, limit: int = 5):
    """Prioritize exact product matches, then fall back to keyword search."""
    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    username = os.getenv("NEO4J_USERNAME", "neo4j")
    password = os.getenv("NEO4J_PASSWORD")
    database = os.getenv("NEO4J_DATABASE", "neo4j")

    if not password:
        raise RuntimeError("Set NEO4J_PASSWORD in PowerShell first.")

    terms = list(dict.fromkeys(
        word.lower()
        for word in re.findall(r"[A-Za-z0-9._-]+", question)
        if len(word) >= 2 and word.lower() not in STOPWORDS
    ))[:12]

    if not terms:
        return []

    cypher = """
    // First retrieve vulnerabilities directly connected to matching products.
    MATCH (v:Vulnerability)-[:AFFECTS_PRODUCT]->(p:Product)
    WITH v, p,
         CASE
           WHEN toLower(coalesce(p.name, '')) CONTAINS $product_term
             OR toLower(coalesce(p.cpeName, '')) CONTAINS $product_term
           THEN 100 ELSE 0
         END AS product_match
    WHERE product_match > 0

    WITH v, collect(DISTINCT p {
        .name, .vendor, .cpeName,
        .versionStartIncluding, .versionStartExcluding,
        .versionEndIncluding, .versionEndExcluding
    })[0..5] AS products

    RETURN v.cveID AS cve_id,
           v.nvdDescription AS description,
           v.shortDescription AS short_description,
           v.vulnerabilityName AS vulnerability_name,
           v.cvssScore AS cvss_score,
           v.cvssSeverity AS severity,
           v.vendorProject AS vendor_project,
           v.product AS kev_product,
           v.requiredAction AS required_action,
           v.knownRansomwareCampaignUse AS ransomware_use,
           products,
           100 AS score
    ORDER BY cvss_score DESC, cve_id ASC
    LIMIT $limit
    """

    # Only use exact product matching when the question contains a product term.
    # Ignore question words and cybersecurity task words when choosing
    # a product term. Prefer longer, distinctive terms such as cpp-httplib.
    ignored_terms = {
        "what", "which", "who", "where", "when", "why", "how",
        "are", "is", "the", "and", "or", "to", "for", "of", "in",
        "on", "with", "from", "about", "affect", "affects",
        "affecting", "impact", "risk", "risks", "most", "severe",
        "severity", "high", "critical", "medium", "low",
        "vulnerability", "vulnerabilities", "product", "products",
        "version", "versions", "fixed", "fix", "patched", "patch",
        "confirmed",
    }

    product_terms = [
        term for term in terms
        if term not in ignored_terms
    ]

    # Prefer the most distinctive term first.
    product_terms.sort(key=len, reverse=True)
# Prioritize an exact CVE ID when the question contains one.
    cve_match = re.search(
        r"\bCVE-\d{4}-\d{4,}\b",
        question,
        re.IGNORECASE,
    )

    if cve_match:
        exact_cve_id = cve_match.group(0).upper()

        exact_cve_query = """
        MATCH (v:Vulnerability)
        WHERE toUpper(coalesce(v.cveID, '')) = $cve_id
        OPTIONAL MATCH (v)-[:AFFECTS_PRODUCT]->(p:Product)
        WITH v, collect(DISTINCT p {
            .name, .vendor, .cpeName,
            .versionStartIncluding, .versionStartExcluding,
            .versionEndIncluding, .versionEndExcluding
        })[0..5] AS products
        RETURN v.cveID AS cve_id,
               v.nvdDescription AS description,
               v.shortDescription AS short_description,
               v.vulnerabilityName AS vulnerability_name,
               v.cvssScore AS cvss_score,
               v.cvssSeverity AS severity,
               v.vendorProject AS vendor_project,
               v.product AS kev_product,
               v.requiredAction AS required_action,
               v.knownRansomwareCampaignUse AS ransomware_use,
               products,
               100 AS score
        LIMIT 1
        """
    with GraphDatabase.driver(uri, auth=(username, password)) as driver:
        driver.verify_connectivity()

        with driver.session(database=database) as session:
            
            if cve_match:
                result = session.run(
                    exact_cve_query,
                    cve_id=exact_cve_id,
                )
                exact_records = [record.data() for record in result]

                if exact_records:
                    return exact_records
                return []

            if product_terms:
                product_term = product_terms[0]
                result = session.run(
                    cypher,
                    product_term=product_term,
                    limit=max(1, min(limit, 10)),
                )
                records = [record.data() for record in result]
                if records:
                    return records

            # Fall back to the previous broad keyword-ranking search.
            fallback = """
            MATCH (v:Vulnerability)
            OPTIONAL MATCH (v)-[:AFFECTS_PRODUCT]->(p:Product)
            WITH v,
                 collect(DISTINCT p {
                     .name, .vendor, .cpeName,
                     .versionStartIncluding, .versionStartExcluding,
                     .versionEndIncluding, .versionEndExcluding
                 })[0..5] AS products,
                 collect(DISTINCT toLower(coalesce(p.name, ''))) AS product_names,
                 collect(DISTINCT toLower(coalesce(p.vendor, ''))) AS product_vendors
            WITH v, products,
                 reduce(score = 0, term IN $terms |
                     score + CASE WHEN
                         toLower(coalesce(v.cveID, '')) CONTAINS term
                         OR toLower(coalesce(v.nvdDescription, '')) CONTAINS term
                         OR toLower(coalesce(v.shortDescription, '')) CONTAINS term
                         OR toLower(coalesce(v.vulnerabilityName, '')) CONTAINS term
                         OR toLower(coalesce(v.vendorProject, '')) CONTAINS term
                         OR toLower(coalesce(v.product, '')) CONTAINS term
                         OR any(name IN product_names WHERE name CONTAINS term)
                         OR any(vendor IN product_vendors WHERE vendor CONTAINS term)
                     THEN 1 ELSE 0 END
                 ) AS score
            WHERE score > 0
            RETURN v.cveID AS cve_id,
                   v.nvdDescription AS description,
                   v.shortDescription AS short_description,
                   v.vulnerabilityName AS vulnerability_name,
                   v.cvssScore AS cvss_score,
                   v.cvssSeverity AS severity,
                   v.vendorProject AS vendor_project,
                   v.product AS kev_product,
                   v.requiredAction AS required_action,
                   v.knownRansomwareCampaignUse AS ransomware_use,
                   products, score
            ORDER BY score DESC, cvss_score DESC
            LIMIT $limit
            """
            result = session.run(
                fallback,
                terms=terms,
                limit=max(1, min(limit, 10)),
            )
            return [record.data() for record in result]


def answer_question(question: str, limit: int = 5):
    started = time.perf_counter()
    records = retrieve_graph_evidence(question, limit)

    if not records:
        return {
            "question": question,
            "answer": (
                "I could not find matching vulnerability evidence in the "
                "current graph. Try a CVE identifier, product name, vendor, "
                "or a more specific vulnerability keyword."
            ),
            "citations": [],
            "retrieved_chunk_ids": [],
            "graph_node_ids": [],
            "latency_ms": round(
                (time.perf_counter() - started) * 1000, 2
            ),
        }

    sources = []
    context_parts = []
    graph_node_ids = []

    for index, record in enumerate(records, start=1):
        cve_id = record.get("cve_id") or f"GRAPH-RESULT-{index}"
        url = (
            f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            if cve_id.startswith("CVE-")
            else ""
        )

        sources.append({
            "id": f"S{index}",
            "title": cve_id,
            "url": url,
        })
        graph_node_ids.append(cve_id)

        # Keep context compact and omit fields that are absent.
        fields = {
            "CVE": cve_id,
            "NVD description": record.get("description"),
            "Fixed version explicitly stated in description": (
                extract_fixed_version(record.get("description"))
            ),
            "KEV description": record.get("short_description"),
            "Vulnerability name": record.get("vulnerability_name"),
            "CVSS score": record.get("cvss_score"),
            "CVSS severity": record.get("severity"),
            "Vendor": record.get("vendor_project"),
            "KEV product": record.get("kev_product"),
            "Required action": record.get("required_action"),
            "Known ransomware use": record.get("ransomware_use"),
            "Connected products": record.get("products"),
        }
        lines = [
            f"{key}: {value}"
            for key, value in fields.items()
            if value is not None and value != "" and value != []
        ]
        context_parts.append(
            f"[S{index}] " + "\n".join(lines)
        )
    version_summary = []

    for record in records:
        cve_id = record.get("cve_id")
        description = record.get("description") or ""

        if not cve_id:
            continue

        fixed_version = extract_fixed_version(description)

        if fixed_version:
            version_summary.append(
                f"{cve_id}: explicitly stated fixed version "
                f"{fixed_version}."
            )
        else:
            version_summary.append(
                f"{cve_id}: no explicitly confirmed fixed version "
                "found in the description."
            )
        version_lines = []
    version_summary = []

    for index, record in enumerate(records, start=1):
        cve_id = record.get("cve_id")
        if not cve_id:
            continue

        fixed_version = extract_fixed_version(
            record.get("description") or ""
        )

        if fixed_version:
            status = f"explicitly stated fixed version {fixed_version}"
        else:
            status = (
                "no explicitly confirmed fixed version found "
                "in the description"
            )

        version_summary.append(f"{cve_id}: {status}.")
        version_lines.append(
            f"- {cve_id}: {status}. [S{index}]"
        )

    # Use Python—not the LLM—as the authority for fixed-version questions.
    version_question = bool(
        re.search(
            r"\b(fix(?:ed|es)?|patch(?:ed|es)?|version|"
            r"upgrade|resolve[sd]?)\b",
            question,
            re.IGNORECASE,
        )
    )
    severity_question = bool(
        re.search(
            r"\b(severest|severe|severity|highest[- ]risk|"
            r"most dangerous|most critical|highest cvss|cvss score)\b",
            question,
            re.IGNORECASE,
        )
    )

    
    if version_question:
        answer_text = (
            "Fixed-version verification based on each CVE's own "
            "description:\n\n"
            + "\n".join(version_lines)
            + "\n\nImportant: 'No explicitly confirmed fixed version' "
            "means the description did not confirm one. It does not "
            "prove that no fix exists."
        )

    elif severity_question:
        def get_cvss_score(record):
            try:
                score = float(record.get("cvss_score"))
                return score if 0.0 <= score <= 10.0 else -1.0
            except (TypeError, ValueError):
                return -1.0

        def get_cvss_severity(score):
            if score < 0:
                return "Unknown"
            if score == 0:
                return "NONE"
            if score < 4:
                return "LOW"
            if score < 7:
                return "MEDIUM"
            if score < 9:
                return "HIGH"
            return "CRITICAL"

        ranked_records = sorted(
            records,
            key=get_cvss_score,
            reverse=True,
        )

        answer_lines = [
            "Vulnerabilities ranked by CVSS score, highest first:"
        ]

        for index, record in enumerate(ranked_records, start=1):
            cve_id = record.get("cve_id") or "Unknown CVE"
            score = get_cvss_score(record)
            description = (
                record.get("short_description")
                or record.get("description")
                or record.get("vulnerability_name")
                or "Description unavailable."
            )

            if score < 0:
                score_text = "CVSS score unavailable"
                severity = "Unknown"
            else:
                score_text = f"CVSS score: {score:.1f}"
                severity = get_cvss_severity(score)

            answer_lines.append(
                f"{index}. {cve_id}: {severity} "
                f"({score_text}). {description} [S{index}]"
            )

        answer_text = "\n\n".join(answer_lines)

    else:
        version_rules = """
VERSION ACCURACY RULES:
- The Python-generated VERSION SUMMARY is authoritative.
- Never invent or change a fixed version.
- Never transfer versions between CVEs.
- An affected-version boundary alone does not confirm a fixed version.
- If no fixed version is confirmed, state that limitation.
- Cite material factual claims using the relevant source ID, such as [S1].
- Do not provide exploit instructions.
"""

        prompt = f"""
You are a cybersecurity threat-intelligence assistant.

Answer the user's question using ONLY the graph evidence below.

STRICT EVIDENCE RULES:
1. Treat each source [S1], [S2], etc. as a separate vulnerability.
2. Never transfer a version number, severity, or detail between CVEs.
3. Do not infer a fixed version from affected-version boundaries.
4. If evidence is missing or ambiguous, state that limitation.
5. Cite material factual claims with the relevant source ID, such as [S1].
6. Do not provide exploit instructions.
7. Use concise, clear language.

GRAPH EVIDENCE:
{chr(10).join(context_parts)}

{version_rules}

PYTHON-GENERATED VERSION SUMMARY:
{chr(10).join(version_summary)}

USER QUESTION:
{question}
"""

        response = ollama.chat(
            model=os.getenv("OLLAMA_MODEL", "llama3.2:3b"),
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.1},
        )

        answer_text = response["message"]["content"]


    return {
        "question": question,
        "answer": answer_text,
        "citations": sources,
        "retrieved_chunk_ids": [],
        "graph_node_ids": graph_node_ids,
        "latency_ms": round(
            (time.perf_counter() - started) * 1000, 2
        ),
    }

