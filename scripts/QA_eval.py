import sys
import types

_vx = types.ModuleType("langchain_community.chat_models.vertexai")
_vx.ChatVertexAI = type("ChatVertexAI", (), {})
sys.modules.setdefault("langchain_community.chat_models.vertexai", _vx)

import langchain_community.llms as _lcl
if not hasattr(_lcl, "VertexAI"):
    _lcl.VertexAI = type("VertexAI", (), {})


# Imports

import json
from datasets import Dataset
from ragas import evaluate
from ragas.metrics import faithfulness, answer_relevancy
from langchain_ollama import ChatOllama, OllamaEmbeddings


# Configuration

INPUT_FILE = "data/multihop_review.json"
OUTPUT_CSV = "ragas_results.csv"
JUDGE_MODEL = "llama3.1:8b"
EMBED_MODEL = "nomic-embed-text"


# Load and map the multi-hop QA data to RAGAS columns

with open(INPUT_FILE, "r", encoding="utf-8-sig") as f:
    raw = json.load(f)

rows = []
for item in raw:
    chunks_raw = item.get("RetrievedChunks", "") or ""
    chunks = [c.strip() for c in chunks_raw.split(",") if c.strip()]
    rows.append({
        "question": item["Question"],
        "answer": item["GeneratedAnswer"],
        "contexts": chunks if chunks else ["[no chunks retrieved]"],
        "ground_truth": item.get("ReferenceAnswer") or "",
    })

dataset = Dataset.from_list(rows)
print(f"Loaded {len(rows)} questions from {INPUT_FILE}")


# Configure the judge (Ollama)

llm = ChatOllama(model=JUDGE_MODEL, temperature=0)
embeddings = OllamaEmbeddings(model=EMBED_MODEL)


# Evaluate

results = evaluate(
    dataset,
    metrics=[faithfulness, answer_relevancy],
    llm=llm,
    embeddings=embeddings,
)

df = results.to_pandas()
df.to_csv(OUTPUT_CSV, index=False)


# Report

# Build a DataFrame that pairs the original question with the metric scores
df_scores = results.to_pandas()

# result.to_pandas() may contain only metric columns; attach questions by index
import pandas as pd
df_out = pd.DataFrame({
    "question": [r["question"] for r in rows],
    "faithfulness": df_scores["faithfulness"].values if "faithfulness" in df_scores else None,
    "answer_relevancy": df_scores["answer_relevancy"].values if "answer_relevancy" in df_scores else None,
})

df_out.to_csv(OUTPUT_CSV, index=False)

print("\nPer-question scores:")
print(df_out.to_string(index=False))

print("\nAverages:")
print(df_out[["faithfulness", "answer_relevancy"]].mean().round(4))