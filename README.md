# XROIQ CAS Public Evidence Verifier

This repository publishes a **sanitized, source-free verifier** for the XROIQ CAS baseline evidence record.

It does not contain the private CAS implementation, governance manuals, golden cases, internal profiles, source package, or full extraction manifest. It validates the structure and internal consistency of the public evidence record without exposing proprietary material.

## What this verifies

- required SHA-256 and Git object identifiers are present and well formed
- the recorded baseline version and scope are fixed
- the recorded test result is exactly `72 passed, 0 failed`
- the frozen-path negative tamper result is `PASS`
- production deployment remains `PROHIBITED`
- high-consequence autonomy remains `PROHIBITED`
- the evidence document has not drifted from the expected public record

## What this does not verify

This public repository cannot independently rebuild or execute the private MVS-001 implementation. It does not prove the underlying private source contents by itself. It verifies a public cryptographic evidence record whose corresponding implementation and detailed audit material remain private.

## Run locally

```bash
python -m pip install -r requirements.txt
python scripts/verify_evidence.py
python -m pytest -q
```

## Public evidence status

- Baseline: `MVS-001 v0.5.1`
- Technical CI result: `72 passed, 0 failed`
- Frozen-path negative tamper test: `PASS`
- Scope: `A1 local/test/shadow only`
- Production deployment: `PROHIBITED`
- High-consequence autonomy: `PROHIBITED`

See [`evidence/baseline-evidence.json`](evidence/baseline-evidence.json) for the public evidence record.

## Security boundary

Do not add implementation code, governance manuals, golden cases, private profiles, source archives, credentials, or internal audit material to this repository. See [`SECURITY.md`](SECURITY.md).
