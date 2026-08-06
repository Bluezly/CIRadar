# Optional LLM layer

The deterministic analyzer remains the source of truth. The optional LLM layer creates a natural-language explanation, a suggested fix, an optional patch, and warnings.

CI Radar uses two different measurements:

- `externality_score` ranges from `-100` for code evidence to `+100` for external evidence.
- `evidence_strength` ranges from `0` to `100` and measures how much evidence supports the diagnosis regardless of direction.

`llm.minimum_score` is retained for configuration compatibility, but it now means minimum evidence strength for automatic enhancement. A code diagnosis with `externality_score=-62` and `evidence_strength=62` is eligible when the configured minimum is `60`.

The threshold applies only to `auto_enhance`. An explicit authenticated request to enhance an analysis is never rejected because of the automatic threshold.

Automatic draft repair additionally requires `Attribution=CODE` and compares `repair.minimum_score` with `code_evidence_score`. The default automatic repair minimum is `60`. Explicit confirmation-gated repair actions do not use the automatic threshold.

It supports OpenAI-compatible chat and embedding endpoints. Remote providers can use a bring-your-own key; trusted local Qwen, Ollama, or compatible endpoints may omit the API key. Results are cached by deterministic input fingerprint and model.

The prompt treats logs, changed file names, and repository content as untrusted data. Raw logs are not sent. Set `send_redacted_excerpt` and `send_changed_files` independently. The prompt sends the signed externality score and separate code, external, and total evidence values so a model cannot mistake a negative code score for low confidence.

Remote embedding failures use the configured similarity fallback.

## Source-grounded repair and data policy

When `send_source_code` is enabled, CI Radar fetches eligible changed files from the exact GitHub commit. It also extracts likely repository paths from common Go, Python, JavaScript/TypeScript and similar stack traces so the model receives code near the failure, not only a log excerpt. Prompt budgeting truncates oversized files rather than silently deleting all source context. Any returned diff is rejected unless it applies exactly to the original, non-truncated fetched source. A valid diff is still a proposal: tests and human review remain mandatory.

`data_policy=local_only` is the safest option for sensitive code and logs. For remote endpoints, CI Radar redacts labeled secrets, common provider tokens, private keys, JWTs, high-entropy values, and Base64/URL-safe Base64 credentials including line-wrapped payloads. `block_on_residual_secret=true` performs a conservative outbound second pass and blocks the request when risk remains. Redaction cannot prove that every organization-specific secret format is removed; operators should use a local model or `metadata_only` for high-sensitivity repositories.

The client supports both OpenAI-compatible Chat Completions and the Responses request shape. These endpoints are not wire-compatible: `/responses` uses `input`, `instructions`, `max_output_tokens`, and `text.format`; chat endpoints use `messages`, `max_tokens`, and `response_format`.
