"""为 Apache mod_ssl 生成自签证书（含 localhost 与常见内网 IP SAN）。"""
from __future__ import annotations

import datetime as dt
import ipaddress
import socket
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _local_ips() -> list[str]:
    ips = {"127.0.0.1", "localhost"}
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    return sorted(ips)


def generate(out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    crt_path = out_dir / "rayscan.crt"
    key_path = out_dir / "rayscan.key"
    if crt_path.exists() and key_path.exists():
        return crt_path, key_path

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    names = _local_ips()
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    san: list[x509.GeneralName] = [x509.DNSName("localhost")]
    for name in names:
        if name == "localhost":
            continue
        try:
            ipaddress.ip_address(name)
            san.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            san.append(x509.DNSName(name))

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1))
        .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .sign(key, hashes.SHA256())
    )

    crt_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return crt_path, key_path


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent / "ssl"
    crt, key = generate(out)
    print(str(crt))
    print(str(key))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
