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
