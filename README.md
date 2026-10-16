# CedarScan evidence pack

Layout: `inputs/` (original files, unmodified; `evidence/lab.py.sha256` guards lab.py), `evidence/` (runner `check.py`, request corpus, expectations, `captured/` real output), `repro/` (F-01 reproduction), `FINDING_REGISTER.md`, `WORK_LOG.md`, `WALKTHROUGH.md`, `AI_USE_NOTE.md`.

Python 3.12.3 (3.10+ works; stdlib only, offline). From this directory:

    python3 inputs/lab.py inputs/requests.json     # original CLI
    python3 evidence/check.py                      # one documented command: run + assert (exit 1 on any change)
    python3 evidence/check.py --selftest           # shows the checker catches injected app changes
    python3 evidence/check.py --capture            # re-record captured output after a reviewed change

Result: F-01 confirmed (high); F-02, F-03 refuted in this model; F-04 confirmed as observation only (low). Fix F-01 first; follow up with a real-browser check of /preview.
