"""Unified lexical and optional semantic retrieval."""

from cyberrisk_intel.retrieval.index import rebuild_index
from cyberrisk_intel.retrieval.search import SearchResult, hybrid_search

__all__ = ["SearchResult", "hybrid_search", "rebuild_index"]
