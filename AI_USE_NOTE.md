# Validation Note

The F-04 finding was retained as a **confirmed header observation, with harm not demonstrated**. The application contract specifies that the absence of a Content-Security-Policy (CSP) header alone does not establish script execution. I verified the finding by running `python .\evidence\check.py` and checking the `f04-preview-headers` result, which returned HTTP 200 with the expected response and header behavior.

I also ran `python .\evidence\check.py --selftest`. All four injected behavior changes were detected, confirming that the checker identifies the tested regressions. These results validate the behavior of the supplied local model; actual browser rendering and deployment behavior remain unverified.