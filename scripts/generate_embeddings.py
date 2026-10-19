import os
import sys

from neo4j import GraphDatabase
from sentence_transformers import SentenceTransformer

URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
USERNAME = os.getenv("NEO4J_USERNAME", "neo4j")
PASSWORD = os.getenv("NEO4J_PASSWORD")
DATABASE = os.getenv("NEO4J_DATABASE", "neo4j")

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
BATCH_SIZE = 32
MAX_CHUNKS = 100000  # Test only; increase after verification.

if not PASSWORD:
    sys.exit("ERROR: Set NEO4J_PASSWORD in PowerShell first.")

print(f"Loading embedding model: {MODEL_NAME}")
model = SentenceTransformer(MODEL_NAME)

driver = GraphDatabase.driver(
    URI,
    auth=(USERNAME, PASSWORD),
)

FETCH_QUERY = """
MATCH (c:Chunk)
WHERE c.text IS NOT NULL
  AND c.embedding IS NULL
RETURN c.id AS id, c.text AS text
ORDER BY c.id
LIMIT $limit
"""

SAVE_QUERY = """
UNWIND $rows AS row
MATCH (c:Chunk {id: row.id})
SET c.embedding = row.embedding,
    c.embeddingModel = $model_name
RETURN count(c) AS updated
"""

try:
    driver.verify_connectivity()

    with driver.session(database=DATABASE) as session:
        rows = session.run(
            FETCH_QUERY,
            limit=MAX_CHUNKS,
        ).data()

    print(f"Fetched {len(rows)} chunks.")

    if not rows:
        print("No chunks need embeddings.")
        sys.exit(0)

    vectors = model.encode(
        [row["text"] for row in rows],
        batch_size=BATCH_SIZE,
        show_progress_bar=True,
        normalize_embeddings=True,
    )

    payload = [
        {
            "id": row["id"],
            "embedding": vector.tolist(),
        }
        for row, vector in zip(rows, vectors)
    ]

    with driver.session(database=DATABASE) as session:
        result = session.run(
            SAVE_QUERY,
            rows=payload,
            model_name=MODEL_NAME,
        ).single()

    print(f"Updated {result['updated']} chunks with embeddings.")

finally:
    driver.close()
