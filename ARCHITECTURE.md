# Structural Architecture — Hackathon Submission

## Request lifecycle

### A. Text/API request
1. API gateway authenticates with `X-Firewall-Token`.
2. `InspectionOrchestrator` assigns a request ID.
3. Input is treated as untrusted data.
4. `ContentNormalizer` creates URL-decoded and Base64-decoded *views* for inspection; it never executes the decoded content.
5. `RuleBasedDetector` evaluates all nine attack classes.
6. Optional LLM adjudicator independently classifies the same untrusted content.
7. Evidence is deduplicated and a risk score is calculated.
8. Policy engine selects `ALLOW`, `SANITIZE`, `REVIEW`, or `BLOCK`.
9. Sanitization occurs only after classification.
10. Only `ALLOW`/`SANITIZE` requests are eligible for downstream AI access.
11. Audit metadata is stored using SHA-256 content hash rather than raw content.

### B. File request
The parser stage chooses an extractor by file type:

- PDF → PDFBox
- DOCX → Apache POI
- HTML → jsoup
- EML → text/header-preserving extraction
- Markdown/source → UTF-8 text
- image → Tesseract OCR

The resulting text then enters the exact same firewall path as a user message. This avoids having separate security logic for each source.

### C. URL request
`WebPageFetcher` accepts only HTTP(S), rejects obvious local/private destinations, downloads a size-bounded response, strips HTML to text, and then passes the result to the same firewall pipeline with `WEB_PAGE` source metadata.

## Attack coverage

| Attack type | Primary rule signal | Secondary signal |
|---|---|---|
| Instruction Override | previous/prior instruction override phrases | LLM classification |
| Role Change | role reassignment phrases | LLM classification |
| Secret Extraction | hidden/system/private secret requests | LLM classification |
| Tool Abuse | tool/command invocation phrases | LLM classification |
| Credential Theft | password/token/API key requests | LLM classification |
| Context Poisoning | fake system/developer/trusted-context markers | LLM classification |
| Multi-Step Jailbreak | staged step/phase pattern | LLM classification |
| Encoded Instructions | Base64 + URL decode inspection | LLM classification |
| Indirect Prompt Injection | external-source + instruction-like content | LLM classification |

## Decision policy

Default thresholds:

```text
risk >= 0.78        → BLOCK
0.48 <= risk < .78  → SANITIZE if evidence exists; otherwise REVIEW
risk < 0.48         → ALLOW if no finding exists
```

These numbers are intentionally configurable; they are **not** presented as universally optimal security thresholds. They should be tuned against a labeled validation set.

## Agentic behavior

The system is not a chat UI with a classifier attached. It is a policy-driven autonomous workflow that:

- selects a parser based on source
- chooses normalization operations
- invokes multiple detectors
- optionally invokes a second model
- resolves evidence into one policy decision
- takes an enforcement action
- records the decision for later inspection
- fails closed for size violations and blocked/review requests

## Observability

Spring Boot Actuator exposes health and metrics endpoints. JPA audit records make each decision traceable through a request ID and content hash. The response also returns the internal stage trace to make the demo explainable.
