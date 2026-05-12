"""GENESIS v7.0 (Tier-9) — reasoning loop layer.

Twelve domain-specific deliberation harnesses (T155-T166) that compress big
reasoning tasks into many small tractable turns. AlphaZero-style: the loop is
the search structure, the LLM is the evaluator.

Public entry point: registry.dispatch(loop_type, session_id, inputs, llm_client)
"""
