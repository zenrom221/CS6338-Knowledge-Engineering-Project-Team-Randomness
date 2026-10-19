"""FastAPI interface for the cybersecurity GraphRAG system."""
from fastapi import FastAPI, HTTPException
from schemas import QueryRequest, QueryResponse
from graphrag_engine import answer_question

app = FastAPI(
    title="Cybersecurity GraphRAG API",
    version="0.2.0",
)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "cybersecurity-graphrag",
    }


@app.post("/query", response_model=QueryResponse)
def query(payload: QueryRequest):
    try:
        result = answer_question(
            payload.question,
            limit=payload.top_k_chunks,
        )
        return QueryResponse(**result)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"GraphRAG query failed: {exc}",
        ) from exc
