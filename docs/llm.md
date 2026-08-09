# Model assistance

Model assistance is optional. CI Radar classifies a failure before any model call and keeps the rule-based result as the primary diagnosis.

When enabled, a model can add an explanation, a suggested fix, and an optional patch. Automatic enhancement uses `evidence_strength` and `llm.minimum_score`; manually requested enhancement is not blocked by that threshold.

Automatic draft repair is more restrictive. It requires a code-attributed diagnosis and compares `code_evidence_score` with `repair.minimum_score`. Repair still produces a proposal; it does not auto-merge changes.

## Endpoints

CI Radar supports OpenAI-compatible chat/Responses endpoints, native Anthropic Messages, and local endpoints such as Ollama-compatible services. Embeddings can use the configured local or remote provider independently of text generation.

## Data sent to a model

Logs, file names, and repository content are treated as untrusted input. Raw logs are not sent. The main controls are:

- `send_redacted_excerpt`
- `send_changed_files`
- `send_source_code`
- `allow_remote_source_code`
- `data_policy`
- `block_on_residual_secret`

With source context enabled, CI Radar fetches eligible files from the exact GitHub commit and caps the number and size of files sent. Returned patches are accepted only when they apply to the original, non-truncated source used for the request.

`local_only` is the safest policy for sensitive repositories. `metadata_only` disables excerpts, changed-file names, and source files. `redacted_remote` allows a remote endpoint after redaction and requires an extra opt-in before source code can leave the host.

Redaction covers common credential formats and configured organization patterns, but it cannot guarantee removal of every private token format. Use local-only or metadata-only mode when that uncertainty is not acceptable.
