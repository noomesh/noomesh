# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Cluster certificate authority.

Self-signed EC P-384 CA plus leaf issuance for the gateway, worker
node-agents, and internal services. Matches the layout and parameters of
certs issued by earlier versions (verified against on-disk certs):

    <pki_dir>/ca.crt, ca.key
    <pki_dir>/gateway/gateway.crt|key      CN=<host>, O=Mesh Cluster Gateway
    <pki_dir>/nodes/<id>/node.crt|key      CN=<id>,   O=Mesh Cluster Node
    <pki_dir>/services/<svc>/service.crt|key  CN=<svc>, O=Mesh Cluster Service

All leaves: ECDSA P-384 / SHA-384, EKU = serverAuth + clientAuth (node
certs double as mTLS client certs; the gateway cert is dual-purpose by
design), default 90-day validity. The CA key never leaves <pki_dir>.

NOTE: this module was historically lost to an unanchored ``pki/`` gitignore
pattern (it ignored the *source* directory along with the cert data dir).
Keep ``.gitignore`` anchored to ``/pki/``.
"""
from __future__ import annotations

import datetime
import ipaddress
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_CA_O = "Mesh Cluster"
_DEFAULT_DAYS = 90


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


class ClusterCA:
    """Cluster CA rooted at ``pki_dir``. Instantiation never writes."""

    def __init__(self, pki_dir: str | Path):
        self.pki_dir = Path(pki_dir)
        self.ca_cert_path = self.pki_dir / "ca.crt"
        self.ca_key_path = self.pki_dir / "ca.key"

    # ── CA ──────────────────────────────────────────────────────────

    def ca_exists(self) -> bool:
        return self.ca_cert_path.exists() and self.ca_key_path.exists()

    def generate_ca(self, cn: str = "Mesh Cluster CA", days: int = 3650) -> tuple[str, str]:
        """Create the self-signed cluster CA (EC P-384). Idempotent-unsafe:
        refuses to overwrite an existing CA."""
        if self.ca_exists():
            raise FileExistsError(f"CA already exists at {self.ca_cert_path}")
        self.pki_dir.mkdir(parents=True, exist_ok=True)

        key = ec.generate_private_key(ec.SECP384R1())
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, _CA_O),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_now() - datetime.timedelta(minutes=5))
            .not_valid_after(_now() + datetime.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .sign(key, hashes.SHA384())
        )
        self._write(self.ca_cert_path, cert.public_bytes(serialization.Encoding.PEM))
        self._write_key(self.ca_key_path, key, mode=0o600)  # operator-only
        return str(self.ca_cert_path), str(self.ca_key_path)

    def _load_ca(self) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
        if not self.ca_exists():
            raise FileNotFoundError(
                f"No cluster CA at {self.pki_dir} — run 'noo security pki init' first"
            )
        cert = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
        key = serialization.load_pem_private_key(self.ca_key_path.read_bytes(), password=None)
        return cert, key

    # ── Leaf issuance ───────────────────────────────────────────────

    def _issue_leaf(
        self,
        cn: str,
        org: str,
        cert_path: Path,
        key_path: Path,
        dns_sans: list[str],
        ip_sans: list[str],
        days: int,
    ) -> tuple[str, str]:
        ca_cert, ca_key = self._load_ca()
        key = ec.generate_private_key(ec.SECP384R1())

        # De-dup while preserving order; drop empties
        dns_seen: list[str] = []
        for d in dns_sans:
            if d and d not in dns_seen:
                dns_seen.append(d)
        ip_seen: list[str] = []
        for i in ip_sans:
            if i and i not in ip_seen:
                ip_seen.append(i)

        sans: list[x509.GeneralName] = [x509.DNSName(d) for d in dns_seen]
        for i in ip_seen:
            try:
                sans.append(x509.IPAddress(ipaddress.ip_address(i)))
            except ValueError:
                sans.append(x509.DNSName(i))  # not an IP — treat as a name

        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, cn),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            ]))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_now() - datetime.timedelta(minutes=5))
            .not_valid_after(_now() + datetime.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(
                x509.ExtendedKeyUsage(
                    [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]
                ),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA384())
        )
        cert_path.parent.mkdir(parents=True, exist_ok=True)
        self._write(cert_path, cert.public_bytes(serialization.Encoding.PEM))
        self._write_key(key_path, key)
        return str(cert_path), str(key_path)

    def issue_node_cert(
        self,
        node_id: str,
        ip: str,
        days: int = _DEFAULT_DAYS,
        extra_sans: Optional[list[str]] = None,
        extra_ips: Optional[list[str]] = None,
    ) -> tuple[str, str]:
        """Cert for a worker node-agent (server + mTLS client)."""
        node_dir = self.pki_dir / "nodes" / node_id
        return self._issue_leaf(
            cn=node_id,
            org="Mesh Cluster Node",
            cert_path=node_dir / "node.crt",
            key_path=node_dir / "node.key",
            dns_sans=[node_id, "localhost", *(extra_sans or [])],
            ip_sans=[ip, "127.0.0.1", *(extra_ips or [])],
            days=days,
        )

    def issue_gateway_cert(
        self,
        hostname: str = "gateway",
        ip: str = "127.0.0.1",
        days: int = _DEFAULT_DAYS,
        extra_sans: Optional[list[str]] = None,
        extra_ips: Optional[list[str]] = None,
    ) -> tuple[str, str]:
        """Dual-purpose (server + client) cert for the gateway."""
        gw_dir = self.pki_dir / "gateway"
        return self._issue_leaf(
            cn=hostname,
            org="Mesh Cluster Gateway",
            cert_path=gw_dir / "gateway.crt",
            key_path=gw_dir / "gateway.key",
            dns_sans=[
                hostname, hostname.lower(), "localhost", "gateway",
                "noo-controller", "noo-gateway", *(extra_sans or []),
            ],
            ip_sans=["127.0.0.1", ip, *(extra_ips or [])],
            days=days,
        )

    def issue_service_cert(
        self,
        service: str,
        hostnames: Optional[list[str]] = None,
        ips: Optional[list[str]] = None,
        days: int = _DEFAULT_DAYS,
    ) -> tuple[str, str]:
        """Cert for an internal service (postgres, nats, redis, ...)."""
        svc_dir = self.pki_dir / "services" / service
        return self._issue_leaf(
            cn=service,
            org="Mesh Cluster Service",
            cert_path=svc_dir / "service.crt",
            key_path=svc_dir / "service.key",
            dns_sans=[service, "localhost", *(hostnames or [])],
            ip_sans=["127.0.0.1", *(ips or [])],
            days=days,
        )

    # ── Inventory / rotation ────────────────────────────────────────

    def _role_of(self, cert_path: Path) -> str:
        rel = cert_path.relative_to(self.pki_dir)
        if rel.parts[0] == "gateway":
            return "gateway"
        if rel.parts[0] == "nodes":
            return "node"
        if rel.parts[0] == "services":
            return "service"
        return "ca" if cert_path.name == "ca.crt" else "other"

    def get_expiring_certs(self, warn_days: int = 30) -> list[dict]:
        """All certs under pki_dir expiring within ``warn_days``."""
        out: list[dict] = []
        for cert_path in sorted(self.pki_dir.rglob("*.crt")):
            # public/ holds the gateway's copies of certs listed here already
            # (noo-cli/src/pki.rs sync_public_view).
            if cert_path.relative_to(self.pki_dir).parts[0] == "public":
                continue
            try:
                cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            except (ValueError, OSError):
                continue
            expires = cert.not_valid_after_utc
            days_left = (expires - _now()).days
            if days_left <= warn_days:
                out.append({
                    "name": str(cert_path.relative_to(self.pki_dir)),
                    "path": str(cert_path),
                    "role": self._role_of(cert_path),
                    "expires": expires.strftime("%Y-%m-%d"),
                    "days_left": days_left,
                })
        return out

    def rotate_all_expiring(self, warn_days: int = 30, new_days: int = _DEFAULT_DAYS) -> list[dict]:
        """Re-issue every expiring LEAF cert, preserving its subject and
        SANs. The CA itself is never rotated here."""
        results: list[dict] = []
        for info in self.get_expiring_certs(warn_days=warn_days):
            if info["role"] in ("ca", "other"):
                continue
            cert_path = Path(info["path"])
            entry = {"name": info["name"], "role": info["role"], "status": "rotated"}
            try:
                old = x509.load_pem_x509_certificate(cert_path.read_bytes())
                cn = old.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                org_attrs = old.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                org = org_attrs[0].value if org_attrs else "Mesh Cluster"
                try:
                    san = old.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                    dns_sans = san.get_values_for_type(x509.DNSName)
                    ip_sans = [str(i) for i in san.get_values_for_type(x509.IPAddress)]
                except x509.ExtensionNotFound:
                    dns_sans, ip_sans = [cn], []
                key_path = cert_path.with_suffix(".key")
                self._issue_leaf(
                    cn=str(cn), org=str(org),
                    cert_path=cert_path, key_path=key_path,
                    dns_sans=list(dns_sans), ip_sans=ip_sans, days=new_days,
                )
            except Exception as e:  # keep rotating the rest
                entry["status"] = "error"
                entry["error"] = str(e)
            results.append(entry)
        return results

    # ── IO helpers ──────────────────────────────────────────────────

    @staticmethod
    def _write(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    @staticmethod
    def _write_key(path: Path, key: ec.EllipticCurvePrivateKey, mode: int = 0o644) -> None:
        # Leaf keys default 0o644: hardened service containers run as
        # non-root users (postgres uid 70, gateway its own user) and read
        # these via ro bind mounts — 0o600 host-owned keys crash-looped the
        # stack on 2026-07-08. The CA key overrides to 0o600 (operator-only;
        # no container needs it). TODO: move leaf keys to compose `secrets:`
        # with per-service uid/mode so host files can tighten too.
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        path.chmod(mode)
