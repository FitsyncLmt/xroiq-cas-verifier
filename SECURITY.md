# Security boundary

This repository is intentionally source-free.

Do not commit or paste:

- CAS implementation code
- governance manuals or internal policy packs
- golden cases, review records, or internal profiles
- source archives or package extractions
- credentials, tokens, private URLs, or unpublished audit evidence
- full internal manifests that disclose proprietary file names or structure

## Reporting accidental disclosure

If sensitive material is committed here:

1. Stop further pushes and do not copy the exposed material into issues or pull requests.
2. Contact the repository owner through a private channel with the affected paths and commit identifiers.
3. Rotate any exposed credentials immediately.
4. Remove the material from the branch and repository history before resuming publication.
5. Review public forks, workflow artifacts, caches, releases, and logs for secondary copies.

Do not report suspected disclosure through a public GitHub issue.

## Vulnerability reports

Report verifier vulnerabilities privately to the repository owner. Include the affected version, reproduction steps, impact, and a suggested remediation when available. Do not include private CAS source or governance material in the report.

## Supported versions

Only the latest tagged verifier release is supported. The verifier validates the published evidence record; it does not grant production approval or authorize high-consequence autonomy.
