"""h2c operator: cert-manager — Certificate, ClusterIssuer, Issuer.

Generates real PEM certificates at conversion time and injects them as
synthetic K8s Secrets into ctx.secrets. Workloads that mount these Secrets
pick them up through the existing volume-mount machinery.

Requires: cryptography
"""

import datetime
import os
import sys

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from helmfile2compose import ConvertResult


# ---- key / cert generation ------------------------------------------------

def _generate_key(algorithm="RSA", key_size=2048):
    """Generate a private key (RSA or ECDSA)."""
    if algorithm.upper() == "ECDSA":
        if key_size <= 256:
            curve = ec.SECP256R1()
        elif key_size <= 384:
            curve = ec.SECP384R1()
        else:
            curve = ec.SECP521R1()
        return ec.generate_private_key(curve)
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def _build_subject(cert_spec):
    """Build an x509.Name from a cert-manager Certificate spec."""
    attrs = []
    cn = cert_spec.get("commonName")
    if cn:
        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    subject = cert_spec.get("subject", {})
    for org in subject.get("organizations", []):
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    for ou in subject.get("organizationalUnits", []):
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    for country in subject.get("countries", []):
        attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
    for locality in subject.get("localities", []):
        attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
    if not attrs:
        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, "h2c-generated"))
    return x509.Name(attrs)


def _parse_duration(duration_str):
    """Parse cert-manager duration (e.g. '87600h') to timedelta."""
    s = duration_str.strip()
    if s.endswith("h"):
        return datetime.timedelta(hours=int(s[:-1]))
    if s.endswith("m"):
        return datetime.timedelta(minutes=int(s[:-1]))
    if s.endswith("s"):
        return datetime.timedelta(seconds=int(s[:-1]))
    return datetime.timedelta(hours=2160)  # 90 days default


def _generate_cert(spec, ca_key=None, ca_cert=None):
    """Generate a certificate from a cert-manager Certificate spec."""
    pk_spec = spec.get("privateKey", {})
    algorithm = pk_spec.get("algorithm", "RSA")
    default_size = 256 if algorithm.upper() == "ECDSA" else 2048
    key_size = pk_spec.get("size", default_size)

    key = _generate_key(algorithm, key_size)
    subject = _build_subject(spec)
    duration = _parse_duration(spec.get("duration", "2160h"))
    now = datetime.datetime.now(datetime.timezone.utc)

    builder = (x509.CertificateBuilder()
               .subject_name(subject)
               .not_valid_before(now)
               .not_valid_after(now + duration)
               .serial_number(x509.random_serial_number())
               .public_key(key.public_key()))

    # Basic constraints
    is_ca = spec.get("isCA", False)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)

    # Subject Key Identifier
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
        critical=False)

    # SAN — dnsNames
    dns_names = spec.get("dnsNames", [])
    if dns_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in dns_names]),
            critical=False)

    # Issuer
    if ca_key and ca_cert:
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_cert.public_key()),
            critical=False)
        signing_key = ca_key
    else:
        builder = builder.issuer_name(subject)
        signing_key = key

    cert = builder.sign(signing_key, hashes.SHA256())
    return key, cert


def _pem_cert(cert):
    """Serialize certificate to PEM string."""
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _pem_key(key):
    """Serialize private key to PEM string (unencrypted PKCS8)."""
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


# ---- converter class -------------------------------------------------------

class CertManagerConverter:
    """Convert cert-manager Certificate/ClusterIssuer/Issuer to Secrets.

    Dispatch order matters: ClusterIssuer and Issuer are indexed first,
    then Certificate processes them all (kinds list order = call order).
    """

    kinds = ["ClusterIssuer", "Issuer", "Certificate"]
    priority = 10  # runs first: generates secrets consumed by trust-manager & keycloak

    def __init__(self):
        self._issuers = {}     # name → {"kind": str, "spec": dict}
        self._generated = {}   # secret_name → {"key": key_obj, "cert": cert_obj}

    def convert(self, kind, manifests, ctx):
        if kind in ("ClusterIssuer", "Issuer"):
            self._index_issuers(manifests)
            return ConvertResult()
        # kind == "Certificate"
        return self._process_certificates(manifests, ctx)

    def _index_issuers(self, manifests):
        for m in manifests:
            name = m.get("metadata", {}).get("name", "")
            if name:
                self._issuers[name] = m.get("spec", {})

    def _process_certificates(self, manifests, ctx):
        # Process in rounds: each round generates certs whose issuer CA is
        # already available, unlocking the next round of CA-issued certs.
        pending = list(manifests)
        while pending:
            batch, still_pending = self._resolve_batch(pending)
            if not batch:
                break
            for merged in self._merge_by_secret(batch):
                self._generate_one(merged, ctx)
            pending = still_pending

        for cert_m in pending:
            name = cert_m.get("metadata", {}).get("name", "?")
            issuer = cert_m.get("spec", {}).get("issuerRef", {}).get("name", "?")
            ctx.warnings.append(
                f"Certificate '{name}' references unresolvable issuer "
                f"'{issuer}' (ACME or missing) — skipped")

        return ConvertResult()

    @staticmethod
    def _merge_by_secret(batch):
        """Group certificates by secretName, merge dnsNames for duplicates.

        In K8s, each namespace has its own Secret. In compose (flat), same
        secretName = same file on disk. Merge all SANs into one cert.
        """
        by_secret = {}
        for cert_m in batch:
            secret_name = cert_m.get("spec", {}).get("secretName", "")
            if secret_name not in by_secret:
                by_secret[secret_name] = cert_m
            else:
                existing = by_secret[secret_name]
                existing_dns = set(existing.get("spec", {}).get("dnsNames", []))
                new_dns = cert_m.get("spec", {}).get("dnsNames", [])
                existing_dns.update(new_dns)
                existing["spec"]["dnsNames"] = sorted(existing_dns)
                existing.setdefault("_merged_from", []).append(
                    cert_m.get("metadata", {}).get("name", "?"))
        return by_secret.values()

    def _generate_one(self, cert_m, ctx):
        """Generate a single certificate and inject it into ctx.secrets."""
        name = cert_m.get("metadata", {}).get("name", "?")
        spec = cert_m.get("spec", {})
        secret_name = spec.get("secretName", "")
        if not secret_name:
            return

        issuer_name = spec.get("issuerRef", {}).get("name", "")
        issuer_spec = self._issuers.get(issuer_name, {})

        ca_key, ca_cert = None, None
        if "ca" in issuer_spec:
            ca_secret = issuer_spec["ca"].get("secretName", "")
            gen = self._generated.get(ca_secret)
            if gen:
                ca_key, ca_cert = gen["key"], gen["cert"]

        key, cert = _generate_cert(spec, ca_key, ca_cert)
        self._generated[secret_name] = {"key": key, "cert": cert}

        string_data = {
            "tls.crt": _pem_cert(cert),
            "tls.key": _pem_key(key),
        }
        if ca_cert:
            string_data["ca.crt"] = _pem_cert(ca_cert)
        elif spec.get("isCA"):
            string_data["ca.crt"] = _pem_cert(cert)

        # Inject as K8s Secret format (stringData, not base64)
        ctx.secrets[secret_name] = {
            "metadata": {"name": secret_name},
            "stringData": string_data,
        }

        # Write to disk — any consumer (workload mounts, Caddy, etc.) can use it
        secret_dir = os.path.join(ctx.output_dir, "secrets", secret_name)
        os.makedirs(secret_dir, exist_ok=True)
        for file_key, file_val in string_data.items():
            with open(os.path.join(secret_dir, file_key), "w",
                       encoding="utf-8") as f:
                f.write(file_val)
        ctx.generated_secrets.add(secret_name)

        merged = cert_m.get("_merged_from", [])
        if merged:
            all_names = [name] + merged
            print(f"  cert-manager: generated {secret_name} "
                  f"(merged {len(all_names)} Certificates: "
                  f"{', '.join(all_names)})", file=sys.stderr)
        else:
            print(f"  cert-manager: generated {secret_name} "
                  f"(Certificate/{name})", file=sys.stderr)

    def _resolve_batch(self, certs):
        """One pass: split certs into resolvable now vs still pending."""
        ready = []
        pending = []
        for cert_m in certs:
            issuer_name = cert_m.get("spec", {}).get(
                "issuerRef", {}).get("name", "")
            issuer_spec = self._issuers.get(issuer_name)

            if issuer_spec is None:
                pending.append(cert_m)
            elif "selfSigned" in issuer_spec:
                ready.append(cert_m)
            elif "ca" in issuer_spec:
                ca_secret = issuer_spec["ca"].get("secretName", "")
                if ca_secret in self._generated:
                    ready.append(cert_m)
                else:
                    pending.append(cert_m)
            else:
                pending.append(cert_m)

        return ready, pending
