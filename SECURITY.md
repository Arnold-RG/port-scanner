# Security Policy — Port Scanner

## Supported version and reporting
Security fixes target the default branch. Use GitHub's private vulnerability reporting when available, or contact the maintainer privately. Do not post targets, service banners, credentials or undisclosed vulnerabilities in public issues.

## Controls for this scanner
- Scan only hosts and port ranges explicitly authorized by their owner.
- Maintain bounded host/port ranges, concurrency and connection timeouts. Do not silently turn a user-approved connect scan into intrusive credential, exploitation or evasion behavior.
- **Privacy:** Scan output, banners and exports may reveal hostnames, software versions and internal topology. Protect output files and remove sensitive details from shared samples.
- **IAM / Cloud:** This CLI requires no stored API tokens, user database or cloud permissions. Do not introduce them without a threat model and secret-handling design.
- **GRC:** Document authorization, scope and report retention for assessments.
- **AI / OT:** Not applicable to default local scanning; introduce only after explicit design and industrial-network safety review where relevant.

## Verification
Require existing Bash/PowerShell lint and smoke tests. Review target parsing, unexpected command execution, filename handling and output encoding when changing scanner behavior.
