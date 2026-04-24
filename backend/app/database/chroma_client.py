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
