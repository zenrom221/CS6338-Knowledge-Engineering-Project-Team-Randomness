"""Pydantic v2 data contracts for a cybersecurity GraphRAG prototype."""
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field, ConfigDict

class EntityType(str, Enum):
    CVE = "CVE"
    SOFTWARE = "Software"
    TECHNIQUE = "Technique"
    MITIGATION = "Mitigation"
    SOURCE_DOCUMENT = "SourceDocument"

class Entity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1, description="Canonical identifier, e.g. CVE-2021-44228 or T1059")
    name: str = Field(min_length=1)
    entity_type: EntityType
    aliases: list[str] = Field(default_factory=list)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    properties: dict[str, Any] = Field(default_factory=dict)

class Relation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_id: str
    predicate: str
    target_id: str
    source_document_id: str
    evidence_text: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    extraction_method: str = "llm"

class TextChunk(BaseModel):
    chunk_id: str
    document_id: str
    text: str
    source_url: str | None = None
    entity_ids: list[str] = Field(default_factory=list)
    embedding: list[float] | None = None

class QueryRequest(BaseModel):
    question: str = Field(min_length=3, max_length=2000)
    top_k_chunks: int = Field(default=5, ge=1, le=20)
    max_hops: int = Field(default=2, ge=1, le=4)
    use_reasoning_rules: bool = True

class QueryResponse(BaseModel):
    question: str
    answer: str
    citations: list[dict[str, str]] = Field(default_factory=list)
    retrieved_chunk_ids: list[str] = Field(default_factory=list)
    graph_node_ids: list[str] = Field(default_factory=list)
    latency_ms: float
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
