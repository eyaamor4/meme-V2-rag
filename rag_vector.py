import json
import os
import pickle
from typing import List, Dict, Any, Tuple

import numpy as np
from sentence_transformers import SentenceTransformer

KB_PATH = os.path.join("knowledge_base", "security_knowledge.json")
CACHE_DIR = ".rag_cache"
EMBED_PATH = os.path.join(CACHE_DIR, "kb_embeddings.npy")
DOCS_PATH = os.path.join(CACHE_DIR, "kb_docs.pkl")

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

# Chargé une seule fois
print(">>> Chargement du modèle d'embedding...")
MODEL = SentenceTransformer(MODEL_NAME)

# Cache mémoire
_DOCS_CACHE: List[Dict[str, Any]] | None = None
_EMBEDDINGS_CACHE: np.ndarray | None = None


def _normalize_text(s: str) -> str:
    return " ".join((s or "").strip().lower().split())


def _build_doc_text(doc: Dict[str, Any]) -> str:
    parts = [
        doc.get("title", ""),
        doc.get("description", ""),
        doc.get("owasp", ""),
        doc.get("cwe", ""),
        " ".join(doc.get("tags", [])) if isinstance(doc.get("tags"), list) else "",
        doc.get("recommendation", ""),
        doc.get("verification", ""),
    ]
    return _normalize_text(" ".join([str(p) for p in parts if p]))


def load_knowledge_base() -> List[Dict[str, Any]]:
    if not os.path.exists(KB_PATH):
        raise FileNotFoundError(f"Base de connaissances introuvable: {KB_PATH}")

    with open(KB_PATH, "r", encoding="utf-8") as f:
        docs = json.load(f)

    if not isinstance(docs, list):
        raise ValueError("Le fichier security_knowledge.json doit contenir une liste JSON.")

    clean_docs = []
    for i, doc in enumerate(docs):
        if not isinstance(doc, dict):
            continue

        item = {
            "id": doc.get("id", f"doc_{i}"),
            "title": doc.get("title", "Non fourni"),
            "description": doc.get("description", "Non fourni"),
            "owasp": doc.get("owasp", "Non fourni"),
            "cwe": doc.get("cwe", "Non fourni"),
            "tags": doc.get("tags", []),
            "recommendation": doc.get("recommendation", "Non fourni"),
            "verification": doc.get("verification", "Non fourni"),
        }
        item["_search_text"] = _build_doc_text(item)
        clean_docs.append(item)

    return clean_docs


def _cosine_similarity_matrix(query_vec: np.ndarray, matrix: np.ndarray) -> np.ndarray:
    query_norm = np.linalg.norm(query_vec) + 1e-12
    matrix_norm = np.linalg.norm(matrix, axis=1) + 1e-12
    sims = np.dot(matrix, query_vec) / (matrix_norm * query_norm)
    return sims


def _keyword_fallback(query: str, docs: List[Dict[str, Any]], top_k: int = 3) -> List[Dict[str, Any]]:
    q = _normalize_text(query)
    q_terms = set(q.split())

    scored = []
    for doc in docs:
        text = doc.get("_search_text", "")
        text_terms = set(text.split())
        score = len(q_terms.intersection(text_terms))
        if score > 0:
            scored.append((score, doc))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [d for _, d in scored[:top_k]]


def build_or_load_index() -> Tuple[List[Dict[str, Any]], np.ndarray]:
    global _DOCS_CACHE, _EMBEDDINGS_CACHE

    if _DOCS_CACHE is not None and _EMBEDDINGS_CACHE is not None:
        return _DOCS_CACHE, _EMBEDDINGS_CACHE

    os.makedirs(CACHE_DIR, exist_ok=True)
    docs = load_knowledge_base()

    if os.path.exists(EMBED_PATH) and os.path.exists(DOCS_PATH):
        try:
            embeddings = np.load(EMBED_PATH)
            with open(DOCS_PATH, "rb") as f:
                cached_docs = pickle.load(f)

            if len(cached_docs) == len(docs):
                _DOCS_CACHE = cached_docs
                _EMBEDDINGS_CACHE = embeddings
                print(">>> Index vectoriel chargé depuis le cache.")
                return _DOCS_CACHE, _EMBEDDINGS_CACHE
        except Exception:
            pass

    print(">>> Construction de l'index vectoriel...")
    texts = [doc["_search_text"] for doc in docs]
    embeddings = MODEL.encode(texts, convert_to_numpy=True, normalize_embeddings=False)

    np.save(EMBED_PATH, embeddings)
    with open(DOCS_PATH, "wb") as f:
        pickle.dump(docs, f)

    _DOCS_CACHE = docs
    _EMBEDDINGS_CACHE = embeddings
    return _DOCS_CACHE, _EMBEDDINGS_CACHE


def retrieve_knowledge(title: str, description: str = "", owasp: str = "", top_k: int = 3) -> List[Dict[str, Any]]:
    query = " ".join([title or "", description or "", owasp or ""]).strip()

    try:
        docs, embeddings = build_or_load_index()

        query_vec = MODEL.encode(query, convert_to_numpy=True, normalize_embeddings=False)
        sims = _cosine_similarity_matrix(query_vec, embeddings)

        idxs = np.argsort(sims)[::-1][:top_k]

        results = []
        for idx in idxs:
            doc = docs[int(idx)].copy()
            doc["score"] = float(sims[int(idx)])
            results.append(doc)

        filtered = [r for r in results if r["score"] > 0.20]
        if filtered:
            return filtered

        return results

    except Exception as e:
        print(f"[RAG] fallback keyword à cause de : {e}")
        docs = load_knowledge_base()
        return _keyword_fallback(query, docs, top_k=top_k)


if __name__ == "__main__":
    results = retrieve_knowledge(
        title="CSP: script-src unsafe-inline",
        description="Content Security Policy allows unsafe-inline in script-src",
        owasp="A05:2021 - Security Misconfiguration",
        top_k=3,
    )

    print(json.dumps(results, ensure_ascii=False, indent=2))