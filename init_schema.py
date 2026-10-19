from pathlib import Path
from neo4j import GraphDatabase
import os

uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
username = os.getenv("NEO4J_USERNAME", "neo4j")
password = os.getenv("NEO4J_PASSWORD")
database = os.getenv("NEO4J_DATABASE", "neo4j")

if not password:
    raise ValueError("Set NEO4J_PASSWORD in your terminal first.")

# Read the schema file from the project directory.
schema_path = Path(__file__).parent / "schema.cypher"
schema = schema_path.read_text(encoding="utf-8")

# Remove full-line comments and split the file into Cypher statements.
lines = [
    line for line in schema.splitlines()
    if not line.strip().startswith(("//", "#"))
]
statements = [
    statement.strip()
    for statement in "\n".join(lines).split(";")
    if statement.strip()
]

with GraphDatabase.driver(uri, auth=(username, password)) as driver:
    driver.verify_connectivity()

    with driver.session(database=database) as session:
        for i, statement in enumerate(statements, start=1):
            try:
                session.run(statement).consume()
                print(f"Statement {i}/{len(statements)}: OK")
            except Exception as exc:
                print(f"Statement {i}/{len(statements)}: FAILED")
                print(exc)
                raise

print("Schema initialization complete.")
