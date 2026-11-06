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

## Scope status

The current implementation has the complete baseline workflow and 100 taxonomy slots, with benchmark-backed rules and metrics. Production hardening still requires deeper rule coverage, authenticated users/projects, formal GitLab merge-request integration, and broader regression data.
