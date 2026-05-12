from __future__ import annotations

from typing import Any

import chromadb
from chromadb.api.async_api import AsyncClientAPI

from app.config import settings

_client: AsyncClientAPI | None = None


async def get_chroma_client() -> AsyncClientAPI:
    global _client
    if _client is None:
        _client = await chromadb.AsyncHttpClient(
            host=settings.chroma_host,
            port=settings.chroma_port,
        )
    return _client


def reset_chroma_client() -> None:
    """Drop the module-level async Chroma client synchronously.

    Same reason as reset_redis_client / reset_mongo_client: the async httpx
    transport owned by the cached client is bound to the previous (now dead)
    event loop. Calling it from a fresh `asyncio.run(...)` raises
    `RuntimeError: Event loop is closed`. Dropping the reference lets the
    next `get_chroma_client()` call build a fresh one on the live loop.
    """
    global _client
    _client = None


# ---------------------------------------------------------------------------
# v1–v4 collections
# ---------------------------------------------------------------------------

async def get_vulnerability_collection() -> Any:
    client = await get_chroma_client()
    return await client.get_or_create_collection(
        name="vulnerabilities",
        metadata={"hnsw:space": "cosine"},
    )


async def add_vulnerability_embedding(
    vuln_id: str,
    title: str,
    description: str,
    severity: str,
) -> None:
    collection = await get_vulnerability_collection()
    document = f"{title}\n{description}\nSeverity: {severity}"
    await collection.add(
        ids=[vuln_id],
        documents=[document],
        metadatas=[{"severity": severity, "title": title}],
    )


async def search_similar_vulnerabilities(
    query: str,
    n_results: int = 10,
) -> list[dict[str, Any]]:
    collection = await get_vulnerability_collection()
    results = await collection.query(
        query_texts=[query],
        n_results=n_results,
        include=["documents", "metadatas", "distances"],
    )

    items: list[dict[str, Any]] = []
    if results and results.get("ids"):
        ids = results["ids"][0]
        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]
        for i, vuln_id in enumerate(ids):
            items.append(
                {
                    "id": vuln_id,
                    "document": docs[i] if i < len(docs) else "",
                    "metadata": metas[i] if i < len(metas) else {},
                    "distance": distances[i] if i < len(distances) else None,
                }
            )
    return items


# ---------------------------------------------------------------------------
# v5 collections — all share the same ChromaDB instance / chroma_data volume.
# Each uses get_or_create_collection so they self-initialise on first access
# with no migration step against the existing four collections.
# ---------------------------------------------------------------------------

async def get_source_corpus_collection() -> Any:
    """T80–T85: source code snippets, AST nodes, function-level chunks.

    Metadata keys: repo, language, file_path, symbol, kind.
    """
    client = await get_chroma_client()
    return await client.get_or_create_collection(
        name="source_corpus",
        metadata={"hnsw:space": "cosine"},
    )


async def get_invariants_collection() -> Any:
    """T83: formal runtime invariants inferred per target.

    Metadata keys: target_id, target_ip, invariant_type, confidence.
    """
    client = await get_chroma_client()
    return await client.get_or_create_collection(
        name="invariants",
        metadata={"hnsw:space": "cosine"},
    )


async def get_hypotheses_collection() -> Any:
    """T87–T89: adversarial hypotheses from the hypothesis market.

    Metadata keys: session_id, hypothesis_type, confidence_stake, status.
    """
    client = await get_chroma_client()
    return await client.get_or_create_collection(
        name="hypotheses",
        metadata={"hnsw:space": "cosine"},
    )


async def get_provenance_collection() -> Any:
    """T103: compressed reasoning trace per confirmed finding.

    Metadata keys: finding_id, session_id, chain_depth.
    """
    client = await get_chroma_client()
    return await client.get_or_create_collection(
        name="provenance",
        metadata={"hnsw:space": "cosine"},
    )


async def get_synthesized_tools_collection() -> Any:
    """T97: self-synthesized tool registry embeddings.

    Metadata keys: tool_name, language, capability_tag, session_created.
    """
    client = await get_chroma_client()
    return await client.get_or_create_collection(
        name="synthesized_tools",
        metadata={"hnsw:space": "cosine"},
    )


# ---------------------------------------------------------------------------
# v6 collections
# ---------------------------------------------------------------------------

async def get_reference_implementations_collection() -> Any:
    """T124: response corpus for popular protocol/format implementations.

    Used by cross_component_diff to compare target behaviour against a
    reference set (nginx, Apache, Caddy, Go json, V8, PyJWT, etc.).

    Metadata keys: protocol, impl_name, impl_version, format.
    """
    client = await get_chroma_client()
    return await client.get_or_create_collection(
        name="reference_implementations",
        metadata={"hnsw:space": "cosine"},
    )


async def get_reward_model_examples_collection() -> Any:
    """T151: few-shot hypothesis→outcome examples for curiosity scorer.

    Metadata keys: was_confirmed (bool as string), session_id, target_class.
    """
    client = await get_chroma_client()
    return await client.get_or_create_collection(
        name="reward_model_examples",
        metadata={"hnsw:space": "cosine"},
    )
