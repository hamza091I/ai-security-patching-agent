# PR #9 Conflict Resolution

PR #9 was opened from `feature/new-task-baraa` before the Phase 2 pull request was merged into `main`. After Phase 2 was merged, GitHub reported a conflict in `scanner/tests.py` because both changes added tests near the end of the same test module.

The conflict was resolved by using the current `main` version as the base, preserving all Phase 2 tests for Projects, Findings, API Keys, and Reports, and appending the RAG tests from PR #9. The RAG fix in `scanner/rag/vector_db.py` was also kept. It now returns `None` safely when a non-exact lookup has no search results instead of indexing an empty list.

Verification after the resolution:

```text
python manage.py check       -> no issues
python manage.py makemigrations --check --dry-run -> no changes
python manage.py test        -> 66 tests passed
```
