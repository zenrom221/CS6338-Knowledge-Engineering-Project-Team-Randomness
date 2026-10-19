import os
from neo4j import GraphDatabase
uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
username = os.getenv("NEO4J_USERNAME", "neo4j")
password = os.getenv("NEO4J_PASSWORD")
database = os.getenv("NEO4J_DATABASE", "neo4j")

if not password:
    raise ValueError("Set the NEO4J_PASSWORD environment variable first.")

with GraphDatabase.driver(
    uri,
    auth=(username, password),
) as driver:
    driver.verify_connectivity()
    print("Successfully connected to Neo4j!")

    with driver.session(database=database) as session:
        result = session.run(
            "RETURN 'GraphRAG database ready' AS message"
        )
        print(result.single()["message"])
