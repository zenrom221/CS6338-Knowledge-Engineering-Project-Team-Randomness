// schema.cypher — Neo4j 5.x+ cybersecurity threat-intelligence graph
CREATE CONSTRAINT cve_id_unique IF NOT EXISTS
FOR (n:CVE) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT software_id_unique IF NOT EXISTS
FOR (n:Software) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT technique_id_unique IF NOT EXISTS
FOR (n:Technique) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT mitigation_id_unique IF NOT EXISTS
FOR (n:Mitigation) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT source_id_unique IF NOT EXISTS
FOR (n:SourceDocument) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT chunk_id_unique IF NOT EXISTS
FOR (n:Chunk) REQUIRE n.id IS UNIQUE;

CREATE INDEX cve_name_idx IF NOT EXISTS FOR (n:CVE) ON (n.name);
CREATE INDEX software_name_idx IF NOT EXISTS FOR (n:Software) ON (n.name);
CREATE INDEX technique_name_idx IF NOT EXISTS FOR (n:Technique) ON (n.name);
CREATE INDEX source_title_idx IF NOT EXISTS FOR (n:SourceDocument) ON (n.title);

CREATE FULLTEXT INDEX threat_text_fulltext IF NOT EXISTS
FOR (n:Chunk|SourceDocument) ON EACH [n.text, n.title];

 // Create these vector indexes only when embeddings have been populated.
 // Example dimensions below assume sentence-transformers/all-MiniLM-L6-v2 (384).
CREATE VECTOR INDEX chunk_embedding_idx IF NOT EXISTS
FOR (n:Chunk) ON (n.embedding)
OPTIONS {indexConfig: {
  `vector.dimensions`: 384,
  `vector.similarity_function`: 'cosine'
}};

CREATE VECTOR INDEX entity_embedding_idx IF NOT EXISTS
FOR (n:Entity) ON (n.embedding)
OPTIONS {indexConfig: {
  `vector.dimensions`: 128,
  `vector.similarity_function`: 'cosine'
}};

// Recommended graph pattern:
// (:CVE)-[:AFFECTS]->(:Software)
// (:CVE)-[:ASSOCIATED_WITH_TECHNIQUE]->(:Technique)
// (:Technique)-[:MITIGATED_BY]->(:Mitigation)
// (:Chunk)-[:MENTIONS]->(:CVE|:Software|:Technique)
// (:SourceDocument)-[:HAS_CHUNK]->(:Chunk)
