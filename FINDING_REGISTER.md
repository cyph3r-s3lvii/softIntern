# Finding register (CedarScan alert validation)

Evidence = request IDs in `evidence/requests_evidence.json`, asserted by `python3 evidence/check.py`; actual output in `evidence/captured/`. Code locations refer to `inputs/lab.py` (unmodified).

| ID | Scanner claim | Disposition | Reachability | Impact | Severity (this model) | Evidence |
|----|---------------|-------------|--------------|--------|-----------------------|----------|
| F-01 | Signed-in red user reads blue reports by changing `report_id` | **Confirmed** | Any valid session + known/guessed `report_id` | Confidential financial forecast of another tenant disclosed; violates contract ("tenants must only read their own reports") | **High** (scanner agrees) | `f01-red-reads-blue` -> 200 `Blue forecast: 340`; `f01-blue-reads-red` -> 200 `Red forecast: 120`; controls `ctl-red-own`, `ctl-blue-own`. Code: lines 23-30; `report["tenant"]` is stored (line 11) but never compared to `tenant` (line 23). |
| F-02 | Query text embedded in HTML without escaping | **Refuted in this model** | `/preview` is public | None demonstrated: `<`, `>`, `&`, `"`, `'` are entity-encoded | None in model | `f02-script-tag` -> `<p>&lt;script&gt;...`; `f02-attr-breakout`; `f02-img-onerror`; `f02-entity-passthrough`. Code: line 20 `html.escape(..., quote=True)`. **Limit:** no browser rendering, charset is not declared in `Content-Type` (line 18), so real-browser behaviour is unproven; this refutes the "no escaping" claim only. |
| F-03 | Report IDs alone disclose content (unauthenticated read) | **Refuted in this model** | Anonymous requests reach `/reports` | None: absent, empty, unknown and case-variant sessions all get 401 `Sign in` | None in model | `f03-no-session-red`, `-blue`, `f03-unknown-session`, `f03-empty-session`, `f03-case-variant-session`. Code: lines 23, 25-26 (`tenant is None` checked before report lookup). Bonus: `f03-no-session-nonexistent-id` gives the same 401, so anonymous callers get no existence oracle. |
| F-04 | No Content-Security-Policy header | **Confirmed as an observation; harm not demonstrated** | Every response (headers built at line 18) | CSP is defense in depth (contract); with F-02 refuted there is no script-execution path shown | Low / informational | `f04-preview-headers`, `f04-reports-headers` assert `Content-Security-Policy` absent. Whether a CSP would change anything in a browser is **unresolved** (model has no browser; contract excludes it). |

Reachability vs impact vs severity: F-01 is reachable by any authenticated tenant and the impact is a confidentiality breach of forecasts -> high. F-02/F-03 are *refuted*, which is different from "unresolved": the code paths were exercised and the outputs show denial / encoding. F-04 is reachable (header absent everywhere) but has no demonstrated impact.

## Top two actions (contract: one immediate fix, one follow-up)
1. **Immediate fix: F-01.** Enforce `report["tenant"] == tenant` at line 29-30 and return the *same* response (404) for "not yours" and "does not exist" so the 200/404 difference seen by signed-in users (`ctl-auth-missing-report` vs `f01-red-reads-blue`) does not become an ID-existence oracle. Add `f01-*` cases as regression tests (they must flip to 404 after the fix; `--selftest` mutant `fix-f01-add-tenant-check` shows the checker flags exactly that flip, so update expectations when the fix lands).
2. **Follow-up investigation: verify `/preview` in a real browser/deployment** (charset, actual rendering of the encoded payloads, and whether adding CSP gives defense in depth). This is the one area the model cannot settle and covers the unresolved parts of F-02 and F-04. F-04 as a standalone fix is deliberately deprioritised.

## Hypothesis refinement
- *Initial hypothesis (F-03):* "report IDs alone disclose content." First check (`f03-no-session-red`) -> 401. Refined, strengthened by `f03-no-session-nonexistent-id`: anonymous responses are identical for valid and invalid IDs, because the auth check precedes the lookup.
- *Initial hypothesis (F-01):* "red can read blue." Check `f01-blue-reads-red` showed the flaw is symmetric: it is a missing ownership check, not something specific to one session.
- *Initial hypothesis (F-02):* "escaping may miss quotes." `f02-attr-breakout` / `f02-img-onerror` refuted it (`&quot;`, `&#x27;`).

## Out-of-contract observation (not one of the four alerts)
`oc-nonstring-query` (`query: 123`) raises `AttributeError` and `oc-unhashable-session` (`session: [..]`) raises `TypeError`. Not XSS or authz; in this CLI one malformed item aborts the whole batch. Contract says routes accept only the documented keys; types are not specified, so this is noted, not rated.

## Engineering-ready reproduction for F-01
```
python3 inputs/lab.py repro/f01_request.json
```
Request 2 (`repro-f01-cross-tenant`: `session: red-reader`, `report_id: r-blue`) returns `status 200`, `body "Blue forecast: 340"`. Expected after fix: 404 (or 403), body must not contain `Blue forecast`. Captured actual output: `repro/f01_actual_output.json`.
**Evidence still missing:** real authentication/session handling, real report ID format/guessability, real HTTP status/logging, and whether any real access to other tenants' reports already happened. None of these exist in the model, and none are assumed.
