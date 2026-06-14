# Compliance Mapping Note

This note complements `production-hardening.md`.

The reference demonstrates an OAuth/OIDC BFF pattern. It is not itself a
compliance artifact.

## Deployment Responsibility

Each deployment must map the pattern to its own requirements, for example:

- FAPI;
- PSD2;
- SOC 2;
- PCI DSS;
- FFIEC guidance;
- internal security standards;
- data retention and privacy requirements.

## Common Mapping Areas

- client authentication method;
- sender-constrained tokens;
- authorization request integrity, such as PAR or JAR;
- audit log retention and SIEM export;
- key management and rotation;
- session lifetime and idle timeout;
- MFA / step-up assurance mapping;
- privileged route authorization;
- incident response;
- backup and disaster recovery;
- vulnerability management and supply-chain controls.

## Important Boundary

The local reference intentionally uses simple local infrastructure. A compliant
deployment must replace or harden infrastructure controls around the same code
pattern.
