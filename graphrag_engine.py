import os
import re
import time
import ollama
from neo4j import GraphDatabase
from sentence_transformers import SentenceTransformer
_embedding_model = None

# sentence-transformers/all-MiniLM-L6-v2
def get_embedding_model():
    global _embedding_model

    if _embedding_model is None:
        _embedding_model = SentenceTransformer(
            "sentence-transformers/all-MiniLM-L6-v2"
        )

    return _embedding_model

def resolve_product_name(raw_name: str, session) -> str:
    # Layer 1: exact match
    result = session.run(
        "MATCH (p:Product) WHERE toLower(p.name) = toLower($name) RETURN p.name LIMIT 1",
        name=raw_name
    )
    record = result.single()
    if record:
        return record["p.name"]
    # Layer 2: fuzzy match (rapidfuzz)
    from rapidfuzz import process
    all_names = [r["p.name"] for r in session.run("MATCH (p:Product) RETURN p.name")]
    match, score, _ = process.extractOne(raw_name, all_names)
    if score >= 90:
        return match
    return raw_name  # unresolved
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




def retrieve_semantic_evidence(session, question: str, limit: int = 5):
    """Retrieve vulnerability evidence using chunk embedding similarity."""

    model = get_embedding_model()

    query_embedding = model.encode(
        question,
        normalize_embeddings=True,
    ).tolist()

    cypher = """
    CALL db.index.vector.queryNodes(
        'chunk_embedding_idx',
        $candidate_count,
        $embedding
    )
    YIELD node AS c, score

    MATCH (v:Vulnerability)-[:HAS_CHUNK]->(c)
    OPTIONAL MATCH (v)-[r:AFFECTS_PRODUCT]->(p:Product)

WITH v, c, score,
     collect(DISTINCT p {
         .name, .vendor, .cpeName,
         versionStartIncluding: r.versionStartIncluding,
         versionStartExcluding: r.versionStartExcluding,
         versionEndIncluding: r.versionEndIncluding,
         versionEndExcluding: r.versionEndExcluding
     })[0..5] AS products

    RETURN c.id AS chunk_id,
           c.text AS chunk_text,
           v.cveID AS cve_id,
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
           score
    ORDER BY score DESC
    LIMIT $limit
    """

    result = session.run(
        cypher,
        embedding=query_embedding,
        candidate_count=min(max(limit * 3, limit), 50),
        limit=max(1, min(limit, 10)),
    )

    return [record.data() for record in result]


def retrieve_graph_evidence(question: str, limit: int = 5):
    if asks_for_affected_versions(question):
        limit = 20
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
        MATCH (v:Vulnerability)-[r:AFFECTS_PRODUCT]->(p:Product)
        WHERE toLower(coalesce(p.name, '')) = $product_term
        OR toLower(coalesce(p.cpeName, '')) CONTAINS $product_term

        WITH v,
            collect(DISTINCT p {
                .name, .vendor, .cpeName,
                versionStartIncluding: r.versionStartIncluding,
                versionStartExcluding: r.versionStartExcluding,
                versionEndIncluding: r.versionEndIncluding,
                versionEndExcluding: r.versionEndExcluding
            })[0..5] AS products


        OPTIONAL MATCH (v)-[:HAS_CHUNK]->(c:Chunk)

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
            collect(DISTINCT c.id) AS chunk_ids,
            100 AS score
        ORDER BY cve_id ASC
        LIMIT $limit
        """



    # Only use exact product matching when the question contains a product term.
    # Ignore question words and cybersecurity task words when choosing
    # a product term. Prefer longer, distinctive terms such as cpp-httplib.
   
    ignored_terms = {
        "what", "which", "who", "where", "when", "why", "how",
        "are", "is", "the", "and", "or", "to", "for", "of", "in",
        "on", "with", "from", "about", "affect", "affects",
        "affecting", "vulnerability", "vulnerabilities",
        "impact", "risk", "risks", "most", "severe", "severity",
        "high", "critical", "medium", "low", "product", "products",
        "version", "versions", "fixed", "fix", "patched", "patch",
        "confirmed",
    }

    
    product_terms = [
        term.strip(".,!?;:'\"()[]{}").lower()
        for term in terms
        if term.strip(".,!?;:'\"()[]{}").lower()
        not in ignored_terms
    ]

    # Search specific product names before vendor names.
    vendor_terms = {"apache"}

    product_terms.sort(
        key=lambda term: (
            term in vendor_terms,
            -len(term),
        )
    )

    print("DEBUG question:", question)
    print("DEBUG terms:", terms)
    print("DEBUG product_terms:", product_terms)
    # Handle explicit product-specific vulnerability questions first.
    product_match = re.search(
        r"\b(cpp-httplib)\b",
        question,
        re.IGNORECASE,
    )

    if product_match and not re.search(
        r"\bCVE-\d{4}-\d{4,}\b",
        question,
        re.IGNORECASE,
    ):
        product_name = product_match.group(1).lower()

        product_query = """
        MATCH (v:Vulnerability)-[r:AFFECTS_PRODUCT]->(p:Product)
        WHERE toLower(coalesce(p.name, '')) = $product_name
           OR toLower(coalesce(p.cpeName, '')) CONTAINS $product_name

        WITH v, collect(DISTINCT p {
            .name, .vendor, .cpeName,
            versionStartIncluding: r.versionStartIncluding,
            versionStartExcluding: r.versionStartExcluding,
            versionEndIncluding: r.versionEndIncluding,
            versionEndExcluding: r.versionEndExcluding
        }) AS products

        OPTIONAL MATCH (v)-[:HAS_CHUNK]->(c:Chunk)

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
               collect(DISTINCT c.id) AS chunk_ids,
               100 AS score
        ORDER BY cve_id ASC
        LIMIT $limit
        """

        with GraphDatabase.driver(
            uri,
            auth=(username, password),
        ) as driver:
            with driver.session(database=database) as session:
                result = session.run(
                    product_query,
                    product_name=product_name,
                    limit=20 if asks_for_affected_versions(question) else 10,
                )
                product_records = [
                    record.data() for record in result
                ]

        if product_records:
            print(
                "DEBUG explicit product results:",
                [r.get("cve_id") for r in product_records],
                flush=True,
            )
            return product_records
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

        OPTIONAL MATCH (v)-[r:AFFECTS_PRODUCT]->(p:Product)
        WITH v,
            collect(DISTINCT p {
                .name, .vendor, .cpeName,
                versionStartIncluding: r.versionStartIncluding,
                versionStartExcluding: r.versionStartExcluding,
                versionEndIncluding: r.versionEndIncluding,
                versionEndExcluding: r.versionEndExcluding
            })[0..5] AS products

        OPTIONAL MATCH (v)-[:HAS_CHUNK]->(c:Chunk)

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
            collect(DISTINCT c.id) AS chunk_ids,
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
                for product_term in product_terms:
                    result = session.run(
                        cypher,
                        product_term=product_term.lower(),
                        limit=max(
                                1,
                                min(limit, 20)
                                if asks_for_affected_versions(question)
                                else min(limit, 10),
                            ),
                    )
                    records = [record.data() for record in result]
                    print(
                        "DEBUG product search:",
                        repr(product_term),
                        "matches:",
                        len(records),
                        )
                    if records:
                        exact_matches = [
                            record for record in records
                            if any(
                                (product.get("name") or "").lower() == product_term.lower()
                                for product in (record.get("products") or [])
                            )
                        ]

                        if exact_matches:
                            return exact_matches

            # Fall back to the previous broad keyword-ranking search.
            fallback = """
            MATCH (v:Vulnerability)
            OPTIONAL MATCH (v)-[r:AFFECTS_PRODUCT]->(p:Product)
            WITH v,
                 collect(DISTINCT p {
                    .name, .vendor, .cpeName,
                    versionStartIncluding: r.versionStartIncluding,
                    versionStartExcluding: r.versionStartExcluding,
                    versionEndIncluding: r.versionEndIncluding,
                    versionEndExcluding: r.versionEndExcluding
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
            
            fallback_result = session.run(
                fallback,
                terms=terms,
                limit=max(1, min(limit, 10)),
            )
            keyword_records = [
                record.data() for record in fallback_result
            ]

            semantic_records = retrieve_semantic_evidence(
                session,
                question,
                limit=limit,
            )

            # Keep keyword matches first, then add semantically relevant
            # vulnerabilities that were not already retrieved.
            combined_records = []
            seen_cves = set()

            for record in keyword_records + semantic_records:
                cve_id = record.get("cve_id")

                if cve_id and cve_id not in seen_cves:
                    seen_cves.add(cve_id)
                    combined_records.append(record)

            result_limit = (
                20 if asks_for_affected_versions(question)
                else max(1, min(limit, 10))
            )
            return combined_records[:result_limit]


def retrieve_top_severity_evidence(
    session,
    limit: int = 5,
    direction: str = "highest",
):
    """Retrieve vulnerabilities ranked by CVSS score."""

    order = "DESC" if direction == "highest" else "ASC"
    score_filter = (
        "v.cvssScore > 0"
        if direction == "lowest"
        else "v.cvssScore IS NOT NULL"
    )
    cypher = f"""
    MATCH (v:Vulnerability)
    WHERE {score_filter}
    WITH v
    ORDER BY v.cvssScore {order}, v.cveID ASC
    LIMIT $limit

    OPTIONAL MATCH (v)-[:HAS_CHUNK]->(c:Chunk)
    OPTIONAL MATCH (v)-[r:AFFECTS_PRODUCT]->(p:Product)

    WITH v,
         collect(DISTINCT c.id) AS chunk_ids,
         collect(DISTINCT p {{
            .name, .vendor, .cpeName,
            versionStartIncluding: r.versionStartIncluding,
            versionStartExcluding: r.versionStartExcluding,
            versionEndIncluding: r.versionEndIncluding,
            versionEndExcluding: r.versionEndExcluding
         }})[0..5] AS products

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
           chunk_ids,
           products
    ORDER BY cvss_score {order}, cve_id ASC
    """

    result = session.run(
        cypher,
        limit=max(1, min(limit, 10)),
    )
    records = [record.data() for record in result]

    print(
        f"SEVERITY DEBUG ({direction}):",
        [(r.get("cve_id"), r.get("cvss_score")) for r in records],
        flush=True,
    )

    return records
 

def asks_for_affected_versions(question: str) -> bool:
    q = question.lower()
    return any(
        phrase in q
        for phrase in (
            "affected version",
            "affected versions",
            "affected version range",
            "version range",
            "version ranges",
            "which versions are vulnerable",
            "vulnerable versions",
        )
    )
def answer_question(question: str, limit: int = 5):
    started = time.perf_counter()
    
    exact_cve_question = bool(
        re.search(r"\bCVE-\d{4}-\d{4,}\b", question, re.IGNORECASE)
    )

    
    product_question = bool(
        re.search(
            r"\b(cpp-httplib)\b",
            question,
            re.IGNORECASE,
        )
    )
    aggregation_question = (   
    product_question
    and bool(
        re.search(
            r"\b(how many|count|counts|count of|"
            r"distribution|breakdown|total number)\b",
            question,
            re.IGNORECASE,
        )
    )
    and bool(
        re.search(
            r"\b(severity|severities|HIGH|MEDIUM|CRITICAL)\b",
            question,
            re.IGNORECASE,
        )
    )
)
    product_severity_question = (
        product_question
        and bool(
            re.search(
                r"\b(most severe|most critical|highest[- ]risk|"
                r"most dangerous|highest[- ]cvss|highest severity)\b",
                question,
                re.IGNORECASE,
            )
        )
    )
    severity_question = (
        not exact_cve_question
        and not product_question
        and bool(
            re.search(
                r"\b(severest|severe|severity|"
                r"highest[- ]risk|lowest[- ]risk|"
                r"most dangerous|most critical|"
                r"highest[- ]cvss|lowest[- ]cvss|"
                r"lowest|highest|cvss scores|"
                r"rank.*cvss|rank.*severity)\b",
                question,
                re.IGNORECASE,
            )
        )
    )

    print(f"DEBUG: question={question!r}, severity_question={severity_question}", flush=True)
    if aggregation_question:
        uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        username = os.getenv("NEO4J_USERNAME", "neo4j")
        password = os.getenv("NEO4J_PASSWORD")
        database = os.getenv("NEO4J_DATABASE", "neo4j")

        if not password:
            raise ValueError(
                "Set NEO4J_PASSWORD in your terminal first."
            )

        aggregation_query = """
        MATCH (v:Vulnerability)-[:AFFECTS_PRODUCT]->(p:Product)
        WHERE toLower(coalesce(p.name, '')) = $product_name
           OR toLower(coalesce(p.cpeName, '')) CONTAINS $product_name

        OPTIONAL MATCH (v)-[:HAS_CHUNK]->(c:Chunk)

        RETURN
            v.cveID AS cve_id,
            v.nvdDescription AS description,
            v.cvssScore AS cvss_score,
            v.cvssSeverity AS severity,
            collect(DISTINCT c.id) AS chunk_ids
        ORDER BY cve_id ASC
        """

        with GraphDatabase.driver(
            uri,
            auth=(username, password),
        ) as driver:
            driver.verify_connectivity()

            with driver.session(database=database) as session:
                result = session.run(
                    aggregation_query,
                    product_name="cpp-httplib",
                )
                retrieved_records = [
                    record.data() for record in result
                ]

        # Deduplicate by CVE ID before counting.
        unique_records = {}
        for record in retrieved_records:
            cve_id = record.get("cve_id")
            if cve_id:
                unique_records[cve_id] = record

        records = list(unique_records.values())

        if not records:
            return {
                "question": question,
                "answer": (
                    "No matching cpp-httplib vulnerability "
                    "records were found in the graph."
                ),
                "citations": [],
                "retrieved_chunk_ids": [],
                "graph_node_ids": [],
                "latency_ms": round(
                    (time.perf_counter() - started) * 1000, 2
                ),
            }

        # Calculate severity counts from every matched CVE.
        counts = {
            "HIGH": 0,
            "MEDIUM": 0,
            "CRITICAL": 0,
            "LOW": 0,
            "NONE": 0,
            "UNKNOWN": 0,
        }

        for record in records:
            severity = str(
                record.get("severity") or "UNKNOWN"
            ).strip().upper()

            if severity not in counts:
                severity = "UNKNOWN"

            counts[severity] += 1

        total = len(records)

        answer_lines = [
            "Severity counts for cpp-httplib, calculated "
            "from all matching vulnerability records in Neo4j:",
            "",
            f"- HIGH: {counts['HIGH']}",
            f"- MEDIUM: {counts['MEDIUM']}",
            f"- CRITICAL: {counts['CRITICAL']}",
        ]

        for severity in ("LOW", "NONE", "UNKNOWN"):
            if counts[severity] > 0:
                answer_lines.append(
                    f"- {severity}: {counts[severity]}"
                )

        answer_lines.extend([
            "",
            f"Total: {total} vulnerabilities.",
        ])

        sources = []
        graph_node_ids = []
        chunk_ids = []

        for index, record in enumerate(records, start=1):
            cve_id = record["cve_id"]

            sources.append({
                "id": f"S{index}",
                "title": cve_id,
                "url": (
                    "https://nvd.nist.gov/vuln/detail/"
                    f"{cve_id}"
                ),
            })

            graph_node_ids.append(cve_id)

            ids = record.get("chunk_ids") or []
            chunk_ids.extend(
                chunk_id for chunk_id in ids if chunk_id
            )

        return {
            "question": question,
            "answer": "\n".join(answer_lines),
            "citations": sources,
            "retrieved_chunk_ids": list(dict.fromkeys(chunk_ids)),
            "graph_node_ids": graph_node_ids,
            "latency_ms": round(
                (time.perf_counter() - started) * 1000, 2
            ),
        }
    if severity_question:
        # Use the same Neo4j connection settings as the existing retriever.
        uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        username = os.getenv("NEO4J_USERNAME", "neo4j")
        password = os.getenv("NEO4J_PASSWORD")
        database = os.getenv("NEO4J_DATABASE", "neo4j")

        if not password:
            raise ValueError("Set NEO4J_PASSWORD in your terminal first.")

        with GraphDatabase.driver(
            uri,
            auth=(username, password),
        ) as driver:
            with driver.session(database=database) as session:
                
                direction = (
                    "lowest"
                    if re.search(
                        r"\b(lowest|lowest[- ]cvss|lowest[- ]risk)\b",
                        question,
                        re.IGNORECASE,
                    )
                    else "highest"
                )

                records = retrieve_top_severity_evidence(
                    session,
                    limit=limit,
                    direction=direction,
                )

    else:
        records = retrieve_graph_evidence(question, limit=limit)



    if not records:
        print(
        "RETRIEVED CVEs:",
        [record.get("cve_id") for record in records],
        flush=True,
        )
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

        for product in record.get("products") or []:
            product_name = product.get("name")
            if product_name:
                graph_node_ids.append(product_name)

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
        context_parts.append(f"[S{index}] " + "\n".join(lines))

    # Classify the question before choosing the answer path.
    affected_version_question = (
        asks_for_affected_versions(question)
        and not product_severity_question
    )

    version_question = (
        not affected_version_question
        and bool(
            re.search(
                r"\b(fix(?:ed|es)?|patch(?:ed|es)?|"
                r"version|upgrade|resolve[sd]?)\b",
                question,
                re.IGNORECASE,
            )
        )
    )

    version_summary = []
    version_lines = []

    # Build fixed-version evidence separately for each CVE.
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

    if affected_version_question and not product_severity_question:
        answer_lines = [
            "Affected-version ranges from the connected product records:"
        ]

        for index, record in enumerate(records, start=1):
            cve_id = record.get("cve_id") or "Unknown CVE"
            products = record.get("products") or []
            ranges = []

            for product in products:
                start_incl = product.get("versionStartIncluding")
                start_excl = product.get("versionStartExcluding")
                end_incl = product.get("versionEndIncluding")
                end_excl = product.get("versionEndExcluding")

                if not any((start_incl, start_excl, end_incl, end_excl)):
                    continue

                lower = (
                    f">= {start_incl}" if start_incl
                    else f"> {start_excl}" if start_excl
                    else None
                )
                upper = (
                    f"<= {end_incl}" if end_incl
                    else f"< {end_excl}" if end_excl
                    else None
                )

                if lower and upper:
                    version_range = f"{lower} and {upper}"
                elif lower:
                    version_range = lower
                elif upper:
                    version_range = upper
                else:
                    version_range = "Version boundary unavailable"

                product_name = product.get("name") or "Unknown product"
                ranges.append(f"{product_name}: {version_range}")

            score = record.get("cvss_score")
            severity = record.get("severity") or "Unknown"

            if score is not None:
                try:
                    score_text = f"CVSS {float(score):.1f}"
                except (TypeError, ValueError):
                    score_text = f"CVSS unavailable"
            else:
                score_text = "CVSS unavailable"

            if ranges:
                answer_lines.append(
                    f"- {cve_id}: {score_text}, {severity}; "
                    f"{'; '.join(ranges)}. [S{index}]"
                )
            else:
                answer_lines.append(
                    f"- {cve_id}: {score_text}, {severity}; "
                    "affected-version range unavailable in the "
                    f"connected product records. [S{index}]"
                )

        answer_text = "\n".join(answer_lines)
    elif product_severity_question:
        ranked_records = sorted(
            records,
            key=lambda record: float(record.get("cvss_score") or -1),
            reverse=True,
        )

        record = ranked_records[0]
        cve_id = record.get("cve_id", "Unknown CVE")
        score = record.get("cvss_score", "Unknown")
        severity = record.get("severity", "Unknown")
        description = record.get("description", "No description available.")

        description = record.get("description", "") or ""

        version_ranges = []

        product_ranges = record.get("products", []) or []

        
        for product in product_ranges:
            if (product.get("name") or "").lower() == "cpp-httplib":
                start = product.get("versionStartIncluding")
                start_excl = product.get("versionStartExcluding")
                end_incl = product.get("versionEndIncluding")
                end_excl = product.get("versionEndExcluding")

                lower = (
                    f">= {start}" if start
                    else f"> {start_excl}" if start_excl
                    else None
                )
                upper = (
                    f"<= {end_incl}" if end_incl
                    else f"< {end_excl}" if end_excl
                    else None
                )

                if lower and upper:
                    version_ranges.append(f"{lower} and {upper}")
                elif lower:
                    version_ranges.append(lower)
                elif upper:
                    version_ranges.append(upper)

        # Fall back to the CVE description if the product record has no range.
        if not version_ranges:
            match = re.search(
                r"(?:prior to|before|versions? below)\s+v?(\d+(?:\.\d+)+)",
                description,
                re.IGNORECASE,
            )
            if match:
                version_ranges.append(f"< {match.group(1)}")

        version_text = (
            "; ".join(version_ranges)
            if version_ranges
            else "Version range not available in the retrieved data"
        )

        selected_source = next(
            (source for source in sources if source["title"] == cve_id),
            None,
        )

        if selected_source:
            sources = [dict(selected_source, id="S1")]

        records = [record]
        graph_node_ids = [cve_id]

        answer_text = (
            f"The most severe vulnerability affecting cpp-httplib is {cve_id}.\n\n"
            f"- CVSS score: {score}\n"
            f"- Severity: {severity}\n"
            f"- What it does: {description}\n"
            f"- Affected versions: {version_text}\n\n"
            f"[S1]"
        )
    elif version_question:
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
            key=lambda record: (
                get_cvss_score(record),
                record.get("cve_id") or "",
            ),
            reverse=(direction == "highest"),
        )

        answer_lines = [
            "Vulnerabilities ranked by CVSS score "
            "(ties are ordered by CVE ID):"
        ]

        source_id_by_cve = {
            source["title"]: source["id"]
            for source in sources
        }

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

            source_id = source_id_by_cve.get(cve_id)
            citation = (
                f"[{source_id}]"
                if source_id
                else "[source unavailable]"
            )

            answer_lines.append(
                f"{index}. {cve_id}: {severity} "
                f"({score_text}). {description} {citation}"
            )

        answer_text = "\n\n".join(answer_lines)

    else:
        version_rules = """
VERSION ACCURACY RULES:
- The Python-generated VERSION SUMMARY is authoritative.
- Never invent or change a fixed version.
- Never transfer versions between CVEs.
- A versionEndExcluding value is an affected-version boundary,
  not automatic proof of a fixed version.
- Phrases such as "prior to version X" describe affected versions
  and must not automatically be reported as a confirmed fix.
- Only report a fixed version when explicitly confirmed by
  reliable evidence for that specific CVE.
- If evidence is missing or ambiguous, say the fixed version
  is not confirmed.
- Cite material factual claims using the relevant source ID,
  such as [S1].
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
        "retrieved_chunk_ids": list(dict.fromkeys(
            chunk_id
            for record in records
            for chunk_id in (
                record.get("chunk_ids", [])
                if isinstance(record.get("chunk_ids"), list)
                else [record.get("chunk_id")]
            )
            if chunk_id
        )),
        "graph_node_ids": graph_node_ids,
        "latency_ms": round(
            (time.perf_counter() - started) * 1000, 2
        ),
    }

