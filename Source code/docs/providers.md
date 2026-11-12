# Provider interfaces

The assistant uses documented HTTPS endpoints on the official hosts. Discovery is live and session-scoped. It stores no provider model cache on disk. OpenAI uses GET /v1/models and POST /v1/responses with store=false. The desktop offers a manual legacy text interface through /v1/chat/completions. Anthropic uses GET /v1/models with after_id pagination and POST /v1/messages with anthropic-version 2023-06-01. Gemini uses GET /v1beta/models with pageToken pagination and POST /v1beta/models/{model}:generateContent.

API access is governed by the credential's provider account, available models, limits and billing. The desktop offers named model presets for each provider, a discovery action and manual model ID entry. Model discovery does not establish that all displayed models support text or tool calls. Disable case tools for text-only models.

The assistant can retrieve and search records approved in the outbound excerpt preview. It can propose navigation, verification, import, collection, annotation and reporting. The desktop displays each proposal with its exact arguments and expiry. Applying a proposal requires local approval. Collection, verification, import and reporting still use the existing operator path and scope controls. Tools have no shell or arbitrary file access. Providers receive the question, approved evidence references, record type, observed time and a short allowlist of numeric fields. The local audit includes provider and model, allowed references and tool outcomes. Responses are displayed as plain text. Credential values and provider error bodies are excluded from the audit.

CLI approval binds the provider, model, question, excerpts and tool scope to the SHA-256 printed by --preview. The desktop defaults to session-only credentials. Saving a key is optional and uses Windows Credential Manager for the current user.

Chat follow-ups send a bounded recent transcript only after it appears in the disclosure preview. The desktop accepts a user-selected local UTF-8 key file and loads its value into the masked session field. An optional case overview shares approved counts, statuses and redacted leads. Current verified and blocked live tests are in verification.md.

Official references verified 2026-11-11:

- https://developers.openai.com/api/reference/resources/models/methods/list
- https://developers.openai.com/api/reference/resources/responses/methods/create
- https://developers.openai.com/api/docs/guides/function-calling
- https://developers.openai.com/api/docs/guides/your-data
- https://platform.claude.com/docs/en/api/models/list
- https://platform.claude.com/docs/en/api/messages/create
- https://aistudio.google.com/api-reference/models
- https://aistudio.google.com/docs/function-calling
