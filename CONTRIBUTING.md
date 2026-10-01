# Contributing
New scenarios need: a clear objective, a **deterministic oracle**, split-canary payloads where applicable, a test, and documented
limitations. Run `pytest -q && ruff check .` before opening a PR. Do not submit scenarios that elicit harmful real-world content;
this project tests *control-flow* failures (injection, leakage, unauthorized actions), not content generation.
