# Product status

## Delivered in this build

- Professional dark security command center in `scanner/templates/scanner/index.html`.
- Dedicated login, registration, and logout pages with Django session authentication.
- Scan API with AST, Bandit, and JavaScript/TypeScript signals.
- Compare API and scan history API.
- Normalized findings with evidence, severity, confidence, risk score, line range, and validation.
- Conservative patch preview with syntax and rescan gates.
- Optional Ollama provider that is isolated from the deterministic baseline.
- 100-category taxonomy and benchmark artifacts from the previous baseline.
- 11 automated Django/unit/API tests.

## Deliberate safety boundaries

The patcher only proposes changes and never writes to a repository. GitHub/GitLab credentials are not accepted by the API. Ollama is optional and must be configured locally. A taxonomy slot is not considered production coverage unless it has a detector and regression evidence.
