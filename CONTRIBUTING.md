# Contributing

Thanks for your interest. This is a one-maintainer project; every change goes through a pull request and is reviewed by the maintainer before it is merged. Direct pushes to `main` are not accepted.

1. Open an issue first for anything larger than a small fix.
2. Fork, make your change on a branch, and keep it focused.
3. From `dev/`, run `python3 selftest.py` and keep it passing (`tools/ci_local.sh` runs the same checks as CI). The no-module baseline packet count is pinned; a change that moves it needs a stated reason.
4. Keep the repository neutral: no real people, companies, credentials, internal hostnames or personal paths in code, comments, docs or test fixtures.
5. Match the existing style, add or update tests with your change, and explain what and why in the pull request.

A pull request needs one approval from the maintainer and a passing CI run before it is merged. Workflow runs from forks need the maintainer's approval before they start.

By contributing you agree that your contribution is licensed under the Apache License 2.0.
