# AI Security Patching Agent

A Django security scanning baseline with a normalized finding contract, Python AST and Bandit engines, JavaScript/TypeScript rules, optional Ollama provider, conservative patch proposals, benchmark evaluation, compare API, and scan history.

## Run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python manage.py migrate
python manage.py test
python scanner/evaluator.py
python manage.py runserver
```

The evaluation pipeline can also be run directly with:

```bash
python scanner/evaluation/benchmark_runner.py
```

It runs the positive and negative benchmark files through the real combined
scanner (`full_security_scan`) and reports TP, TN, FP, FN, precision, recall,
F1-score, accuracy, and the failed benchmark cases.

## APIs

- `POST /api/scan/` — scan, normalize, save history, and return a validated patch proposal.
- `POST /api/compare/` — compare AST/Bandit/JavaScript engine outputs without saving a scan.
- `GET /api/history/` — latest saved scans and finding counts.

Example:

```bash
curl -X POST http://127.0.0.1:8000/api/scan/ -H 'Content-Type: application/json' -d '{"filename":"sample.py","code":"value = eval(user_input)"}'
```

All findings include engine, language, CWE, rule, severity, confidence, risk score, line range, evidence, recommendation, and validation fields. Ollama is optional and is never required for the deterministic baseline. Patches are proposals only; this project does not push to GitHub/GitLab automatically.

## Phase 2 SaaS workflow

The merged SaaS foundation supports SQLite for local work and PostgreSQL through `DATABASE_URL` for deployment. The dashboard now exposes workspace-scoped Projects, Findings workflow, and Reports sections.

```text
GET/POST /api/v1/projects/
GET      /api/v1/findings/?status=OPEN
PATCH    /api/v1/findings/<id>/
GET/POST /api/v1/api-keys/
POST     /api/v1/api-keys/<prefix>/revoke/
GET      /api/v1/reports/export/?type=json|csv|sarif
```

API keys are created once and stored as SHA-256 digests. CI clients can authenticate with `Authorization: Bearer sa_...`. SARIF output is suitable for a later GitHub Code Scanning integration. See `docs/PHASE2_RELEASE_NOTES.md` for the complete contract and boundaries.

## Phase 3 durable scan jobs

The SaaS workflow now supports durable scan jobs. Create a job with `POST /api/v1/scan-jobs/`; the API returns `202 Accepted` and a job ID. Poll `GET /api/v1/scan-jobs/<id>/` for progress and the final result. Use an `Idempotency-Key` header when a client may retry the request.

```bash
python manage.py process_scan_jobs --limit 10
```

Run the worker in a separate process during local development. It persists the final scan, findings, patch proposal, and engine breakdown. The dashboard uses this job API and polls progress instead of waiting for the scanner in the request. `MAX_SCAN_BYTES` defaults to 1 MB and can be changed in `.env`. See `docs/PHASE3_RELEASE_NOTES.md` for the full contract.

## Scope status

The current implementation has the complete baseline workflow and 100 taxonomy slots, with benchmark-backed rules and metrics. Production hardening still requires deeper rule coverage, authenticated users/projects, formal GitLab merge-request integration, and broader regression data.
