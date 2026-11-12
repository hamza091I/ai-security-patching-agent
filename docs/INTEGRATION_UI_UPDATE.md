# Integration UI Update

This update adds a dashboard workflow for repository integrations. Users can now create a GitHub or GitLab integration from the Projects/Dashboard page, start the provider OAuth flow, load repositories, and queue a remote scan of the configured default branch.

## Local workflow

1. Start Django with `python manage.py runserver`.
2. Start the scan worker with `python manage.py process_scan_jobs` (or run it in a loop during development).
3. Log in at `http://127.0.0.1:8000/`.
4. Use the new **Repository integrations** section to add the repository.
5. Click **Connect OAuth**, approve GitHub, then use **Load repositories** and **Sync default branch**.

The archive intentionally excludes `.env`, `db.sqlite3`, virtual environments, caches, and Git metadata. Configure local credentials from `.env.example` after copying the project.
