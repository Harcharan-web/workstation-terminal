# Security policy

sshweb provides shell access through a web browser, so treat every bug in authentication,
authorisation, origin checking, session handling or process management as a potential
vulnerability.

- **Threat model, mitigations and known limitations:** [docs/SECURITY.md](docs/SECURITY.md)
- **Authentication protocol:** [docs/AUTHENTICATION.md](docs/AUTHENTICATION.md)

## Reporting

Please report suspected vulnerabilities privately to the maintainer, not in a public issue.
Include the version (`sshweb version`), your configuration with secrets removed, and reproduction steps.

## Secure defaults

- Listens on 127.0.0.1 only. Network exposure needs `allow_remote_access: true` **and** TLS.
- No password or unauthenticated login of any kind, and no hard-coded credentials.
- SSH host keys are verified strictly against an administrator-managed `known_hosts`.
- Refuses to start as root, or with unsafe permissions on its authorisation or key files.
- Terminal contents are never logged.
