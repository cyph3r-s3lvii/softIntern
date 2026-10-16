# Walkthrough (text equivalent, ~3 min)

1. Run `python3 evidence/check.py`. It replays the original three requests plus 19 evidence requests through the unmodified `inputs/lab.py` CLI and asserts status, exact body and headers for each, then compares to `evidence/captured/`.
2. F-01: `f01-red-reads-blue` returns 200 "Blue forecast: 340". Controls show own-report reads work. Line 29-30 of lab.py never checks `report["tenant"]`. Confirmed, high.
3. F-03: five anonymous/invalid-session probes all return 401. Refuted in this model.
4. F-02: script, attribute-breakout and entity payloads all come back encoded. Refuted in this model; browser rendering is out of scope.
5. F-04: header absent, confirmed, but nothing demonstrates script execution, so low.
6. `python3 evidence/check.py --selftest` shows the checker fails when behaviour is changed.
7. Decision: fix F-01 now; investigate `/preview` in a real browser next.
