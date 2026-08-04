# Optional LLM layer

The deterministic analyzer remains the source of truth. The optional LLM layer creates a natural-language explanation, a suggested fix, an optional patch, and warnings.

It supports OpenAI-compatible chat and embedding endpoints with a bring-your-own-key configuration. Results are cached by deterministic input fingerprint and model.

The prompt treats logs, changed file names, and repository content as untrusted data. Raw logs are not sent. Set `send_redacted_excerpt` and `send_changed_files` independently.

Remote embedding failures fall back to the local feature-hash vector similarity engine.
