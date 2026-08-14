# GitHub Publishing Checklist

Use this checklist before making the repository public or sharing it with recruiters.

## Add To Git

```bash
git add .dockerignore .gitignore .rgignore README.md docs/
git add show_alerts.sh security-demo-lab web_early_warning uml
```

Then review:

```bash
git status --short
git diff --cached --stat
```

## Keep Out Of Git

- `.venv/`, `__pycache__/`, local editor/agent state.
- Raw datasets such as `flowFeatures.csv`.
- Runtime logs under `security-demo-lab/logs/`.
- SQLite alert history files such as `alerts.db`.
- Private report drafts or personal documents.
- Private webhook URLs, bot tokens, API keys, n8n credentials, chat IDs.
- Large `.joblib` model bundles unless you intentionally publish them and have permission to do so.

## Recommended Repository Description

```text
ML-based web threat early-warning pipeline from Nginx access logs to FastAPI scoring, SQLite alert history, n8n workflow, and Docker demo lab.
```

## Suggested First Commit

```bash
git commit -m "Prepare web threat early warning project for portfolio"
```

## Notes For Reviewers

The public repository demonstrates the engineering pipeline and reproducible local lab. Model bundles and raw datasets may be distributed separately because they are large and may have licensing or privacy constraints.

