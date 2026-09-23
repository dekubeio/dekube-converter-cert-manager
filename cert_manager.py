"""dekube converter: cert-manager — Certificate, ClusterIssuer, Issuer.

Generates real PEM certificates at conversion time and injects them as
synthetic K8s Secrets into ctx.secrets. Workloads that mount these Secrets
pick them up through the existing volume-mount machinery.

Requires: cryptography
"""

import datetime
import os
import re
import sys

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from dekube import ConverterResult, Converter  # pylint: disable=import-error  # h2c resolves at runtime


# Go time.ParseDuration units (cert-manager duration/renewBefore format)
_GO_DURATION_RE = re.compile(r'(\d+(?:\.\d*)?|\.\d+)(ns|us|µs|μs|ms|s|m|h)')
_GO_UNITS = {"ns": 1e-9, "us": 1e-6, "µs": 1e-6, "μs": 1e-6, "ms": 1e-3,
             "s": 1, "m": 60, "h": 3600}

# cert-manager usages → x509 KeyUsage flags / EKU OIDs
_KEY_USAGE_FLAGS = {
    "digital signature": "digital_signature", "signing": "digital_signature",
    "content commitment": "content_commitment", "key encipherment": "key_encipherment",
    "key agreement": "key_agreement", "data encipherment": "data_encipherment",
    "cert sign": "key_cert_sign", "crl sign": "crl_sign",
    "encipher only": "encipher_only", "decipher only": "decipher_only",
}
_EXT_KEY_USAGES = {
    "server auth": ExtendedKeyUsageOID.SERVER_AUTH, "client auth": ExtendedKeyUsageOID.CLIENT_AUTH,
    "code signing": ExtendedKeyUsageOID.CODE_SIGNING,
    "email protection": ExtendedKeyUsageOID.EMAIL_PROTECTION,
    "timestamping": ExtendedKeyUsageOID.TIME_STAMPING, "ocsp signing": ExtendedKeyUsageOID.OCSP_SIGNING,
}
_KU_FIELDS = ("digital_signature", "content_commitment", "key_encipherment", "data_encipherment",
              "key_agreement", "key_cert_sign", "crl_sign", "encipher_only", "decipher_only")


# ---- converter class -------------------------------------------------------

class CertManagerConverter(Converter):  # pylint: disable=too-few-public-methods  # contract: one class, one method
    """Convert cert-manager Certificate/ClusterIssuer/Issuer to Secrets.

    Dispatch order matters: ClusterIssuer and Issuer are indexed first,
    then Certificate processes them all (kinds list order = call order).
    """

    name = "cert-manager"
    kinds = ["ClusterIssuer", "Issuer", "Certificate"]
    priority = 100  # runs first: generates secrets consumed by trust-manager & keycloak

    def __init__(self):
        self._issuers = {}     # name → issuer spec dict
        self._generated = {}   # secret_name → {"key": key_obj, "cert": cert_obj}

    def convert(self, kind, manifests, ctx):
        """Dispatch to issuer indexer or certificate processor."""
        if kind in ("ClusterIssuer", "Issuer"):
            self._index_issuers(manifests)
            return ConverterResult()
        # kind == "Certificate"
        return self._process_certificates(manifests, ctx)

    def _index_issuers(self, manifests):
        for m in manifests:
            name = (m.get("metadata") or {}).get("name", "")
            if name:
                self._issuers[name] = m.get("spec") or {}

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
            name = (cert_m.get("metadata") or {}).get("name", "?")
            issuer = ((cert_m.get("spec") or {}).get("issuerRef") or {}).get("name", "?")
            ctx.warnings.append(
                f"Certificate '{name}' references unresolvable issuer "
                f"'{issuer}' (ACME or missing) — skipped")

        return ConverterResult()

    @staticmethod
    def _merge_by_secret(batch):
        """Group certificates by secretName, merge dnsNames for duplicates.

        In K8s, each namespace has its own Secret. In compose (flat), same
        secretName = same file on disk. Merge all SANs into one cert.
        """
        by_secret = {}
        for cert_m in batch:
            secret_name = (cert_m.get("spec") or {}).get("secretName", "")
            if secret_name not in by_secret:
                by_secret[secret_name] = cert_m
            else:
                existing = by_secret[secret_name]
                existing_dns = set((existing.get("spec") or {}).get("dnsNames") or [])
                new_dns = (cert_m.get("spec") or {}).get("dnsNames") or []
                existing_dns.update(new_dns)
                existing["spec"]["dnsNames"] = sorted(existing_dns)
                existing.setdefault("_merged_from", []).append(
                    (cert_m.get("metadata") or {}).get("name", "?"))
        return by_secret.values()

    def _generate_one(self, cert_m, ctx):
        """Generate a single certificate and inject it into ctx.secrets."""
        name = (cert_m.get("metadata") or {}).get("name", "?")
        spec = cert_m.get("spec") or {}
        secret_name = spec.get("secretName", "")
        if not secret_name:
            return

        issuer_name = (spec.get("issuerRef") or {}).get("name", "")
        issuer_spec = self._issuers.get(issuer_name) or {}

        ca_key, ca_cert = None, None
        if "ca" in issuer_spec:
            ca_secret = (issuer_spec.get("ca") or {}).get("secretName", "")
            gen = self._generated.get(ca_secret)
            if gen:
                ca_key, ca_cert = gen["key"], gen["cert"]

        key, cert = self._generate_cert(spec, ca_key, ca_cert)
        self._generated[secret_name] = {"key": key, "cert": cert}

        string_data = {
            "tls.crt": self._pem_cert(cert),
            "tls.key": self._pem_key(key),
        }
        if ca_cert:
            string_data["ca.crt"] = self._pem_cert(ca_cert)
        elif spec.get("isCA"):
            string_data["ca.crt"] = self._pem_cert(cert)

        # Inject as K8s Secret format (stringData, not base64)
        ctx.secrets[secret_name] = {
            "metadata": {"name": secret_name},
            "stringData": string_data,
        }

        # Write to disk — any consumer (workload mounts, Caddy, etc.) can use it
        secret_dir = os.path.join(ctx.output_dir, "secrets", secret_name)
        os.makedirs(secret_dir, exist_ok=True)
        out_real = os.path.realpath(ctx.output_dir) + os.sep
        for file_key, file_val in string_data.items():
            out_path = os.path.join(secret_dir, file_key)
            if not os.path.realpath(out_path).startswith(out_real):
                continue
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(file_val)
        ctx.generated_secrets.add(secret_name)

        merged = cert_m.get("_merged_from") or []
        if merged:
            all_names = [name] + merged
            print(f"  cert-manager: generated {secret_name} "
                  f"(merged {len(all_names)} Certificates: "
                  f"{', '.join(all_names)})", file=sys.stderr)
        else:
            print(f"  cert-manager: generated {secret_name} "
                  f"(Certificate/{name})", file=sys.stderr)

    @staticmethod
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

    @staticmethod
    def _build_subject(cert_spec):
        """Build an x509.Name from a cert-manager Certificate spec."""
        attrs = []
        cn = cert_spec.get("commonName")
        if cn:
            attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
        subject = cert_spec.get("subject") or {}
        for org in (subject.get("organizations") or []):
            attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
        for ou in (subject.get("organizationalUnits") or []):
            attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
        for country in (subject.get("countries") or []):
            attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
        for locality in (subject.get("localities") or []):
            attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
        if not attrs:
            attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, "h2c-generated"))
        return x509.Name(attrs)

    @staticmethod
    def _parse_duration(duration_str):
        """Parse a Go duration (e.g. '87600h0m0s', '1h30m', '2160h') to timedelta."""
        default = datetime.timedelta(hours=2160)  # cert-manager default: 90 days
        s = duration_str.strip() if isinstance(duration_str, str) else ""
        pos, seconds = 0, 0.0
        for m in _GO_DURATION_RE.finditer(s):
            if m.start() != pos:
                return default
            seconds += float(m.group(1)) * _GO_UNITS[m.group(2)]
            pos = m.end()
        if not s or pos != len(s) or seconds <= 0:
            return default
        return datetime.timedelta(seconds=seconds)

    @staticmethod
    def _usage_extensions(spec, is_ca, algorithm):
        """KeyUsage (critical) + optional ExtendedKeyUsage, cert-manager semantics.

        Default usages: digital signature + key encipherment (cert-manager
        pkg/apis/certmanager/v1 DefaultKeyUsages, consumed by pkg/util/pki/csr.go
        — server auth is deliberately NOT a default, since it breaks clients
        when isCA: true).
        CAs always get cert sign + crl sign — strict X.509 verifiers (Python >= 3.13,
        openssl -x509_strict) reject a CA without KeyUsage.
        """
        usages = [u for u in (spec.get("usages") or []) if isinstance(u, str)]
        usages = usages or ["digital signature", "key encipherment"]
        flags = {_KEY_USAGE_FLAGS[u] for u in usages if u in _KEY_USAGE_FLAGS}
        if is_ca:
            flags |= {"key_cert_sign", "crl_sign", "digital_signature"}
        if algorithm.upper() != "RSA":
            flags.discard("key_encipherment")  # CBA: RSA-only semantics; revisit if cert-manager differs
        if "key_agreement" not in flags:
            flags -= {"encipher_only", "decipher_only"}
        if not flags:
            flags.add("digital_signature")  # RFC 5280 §4.2.1.3: KeyUsage MUST NOT be all-false
        exts = [(x509.KeyUsage(**{f: f in flags for f in _KU_FIELDS}), True)]
        ekus = [_EXT_KEY_USAGES[u] for u in usages if u in _EXT_KEY_USAGES]
        if ekus:
            exts.append((x509.ExtendedKeyUsage(ekus), False))
        return exts

    def _generate_cert(self, spec, ca_key=None, ca_cert=None):
        """Generate a certificate from a cert-manager Certificate spec."""
        pk_spec = spec.get("privateKey") or {}
        algorithm = pk_spec.get("algorithm") or "RSA"
        default_size = 256 if algorithm.upper() == "ECDSA" else 2048
        key_size = pk_spec.get("size") or default_size

        key = self._generate_key(algorithm, key_size)
        subject = self._build_subject(spec)
        duration = self._parse_duration(spec.get("duration"))
        now = datetime.datetime.now(datetime.timezone.utc)

        builder = (x509.CertificateBuilder()
                   .subject_name(subject)
                   .not_valid_before(now)
                   .not_valid_after(now + duration)
                   .serial_number(x509.random_serial_number())
                   .public_key(key.public_key()))

        # Basic constraints
        is_ca = bool(spec.get("isCA"))
        builder = builder.add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)

        # KeyUsage / ExtendedKeyUsage — strict X.509 verifiers reject a cert without these
        for ext, critical in self._usage_extensions(spec, is_ca, algorithm):
            builder = builder.add_extension(ext, critical=critical)

        # Subject Key Identifier
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False)

        # SAN — dnsNames
        dns_names = spec.get("dnsNames") or []
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

    @staticmethod
    def _pem_cert(cert):
        """Serialize certificate to PEM string."""
        return cert.public_bytes(serialization.Encoding.PEM).decode()

    @staticmethod
    def _pem_key(key):
        """Serialize private key to PEM string (unencrypted PKCS8)."""
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

    def _resolve_batch(self, certs):
        """One pass: split certs into resolvable now vs still pending."""
        ready = []
        pending = []
        for cert_m in certs:
            issuer_name = ((cert_m.get("spec") or {}).get(
                "issuerRef") or {}).get("name", "")
            issuer_spec = self._issuers.get(issuer_name)

            if issuer_spec is None:
                pending.append(cert_m)
            elif "selfSigned" in issuer_spec:
                ready.append(cert_m)
            elif "ca" in issuer_spec:
                ca_secret = (issuer_spec.get("ca") or {}).get("secretName", "")
                if ca_secret in self._generated:
                    ready.append(cert_m)
                else:
                    pending.append(cert_m)
            else:
                pending.append(cert_m)

        return ready, pending
