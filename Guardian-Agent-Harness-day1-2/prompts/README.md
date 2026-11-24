# AI boundary

This release uses deterministic specialist stages, not an LLM. It requires no API key and does not send source code to a model. Evidence records contain `ai_inference: []` explicitly. Repository comments, package metadata and commit messages never become instructions.

A future model adapter must produce separate inference records with model identity and prompt hash, cite existing verified observations, operate with read-only tools, and must not approve baselines, review findings as a human, approve lessons or suppress protected findings. Do not describe the current deterministic pipeline as an autonomous reasoning model.
