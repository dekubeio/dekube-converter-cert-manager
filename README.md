# h2c-operator-certmanager

![vibe coded](https://img.shields.io/badge/vibe-coded-ff69b4)
![python 3](https://img.shields.io/badge/python-3-3776AB)
![heresy: 6/10](https://img.shields.io/badge/heresy-6%2F10-orange)
![public domain](https://img.shields.io/badge/license-public%20domain-brightgreen)

cert-manager CRD converter for [helmfile2compose](https://github.com/helmfile2compose/h2c-core).

## Handled kinds

- `Certificate` -- generates real PEM certificates and injects them as synthetic K8s Secrets
- `ClusterIssuer` -- indexed for issuer resolution (no output)
- `Issuer` -- indexed for issuer resolution (no output)

## What it does

Replaces cert-manager's certificate issuance with local generation at conversion time. Produces real PEM files (CA chains, leaf certs) that workloads pick up through the existing Secret volume-mount machinery.

- Generates ECDSA or RSA private keys based on `spec.privateKey`
- Builds X.509 subjects from `spec.commonName` and `spec.subject`
- Adds SAN entries from `spec.dnsNames`
- Supports self-signed certificates (via `selfSigned` issuers) and CA-issued certificates (via `ca` issuers referencing a generated CA Secret)
- Processes certificates in rounds: self-signed CAs first, then CA-issued leaf certs, unlocking dependent chains
- Merges certificates that target the same `secretName` across namespaces (compose is flat -- same secretName = same file on disk, all SANs merged into one cert)
- Writes `tls.crt`, `tls.key`, and `ca.crt` to `secrets/<secretName>/`
- Injects results into `ctx.secrets` as K8s Secret format (`stringData`), making them available to downstream operators (trust-manager, keycloak) and workload volume mounts
- Certificates referencing ACME or missing issuers are skipped with a warning

## Priority

`10` -- runs first. Generates secrets consumed by trust-manager (priority 20) and keycloak (priority 50).

## Dependencies

- `cryptography` (listed in `requirements.txt`)

Install:

```bash
pip install -r requirements.txt
```

## Usage

Via h2c-manager (recommended):

```bash
python3 h2c-manager.py certmanager
```

Manual:

```bash
python3 helmfile2compose.py --extensions-dir ./h2c-operator-certmanager --helmfile-dir ~/my-platform -e local --output-dir .
```

## License

Public domain.
