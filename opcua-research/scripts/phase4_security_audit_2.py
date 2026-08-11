import asyncio
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from asyncua import Client
from asyncua.ua.uaerrors import UaError

from rich.console import Console
from rich.panel import Panel
from rich.table import Table


console = Console(record=True)

SERVER_URL = "opc.tcp://127.0.0.1:4840"

CERT_PATH = "untrusted_cert_2.pem"
KEY_PATH = "untrusted_key_2.pem"

# A deliberately different identity from the first certificate test.
TEST_APPLICATION_URI = "urn:freeopcua:client:independent-test"


# ---------------------------------------------------------------------------
# Certificate Generation
# ---------------------------------------------------------------------------

def generate_independent_self_signed_certificate(
    cert_path: str = CERT_PATH,
    key_path: str = KEY_PATH,
    application_uri: str = TEST_APPLICATION_URI,
):
    """
    Generate a completely independent self-signed OPC UA client certificate.

    The certificate:
      - uses a newly generated RSA keypair
      - is self-signed
      - has a unique Application URI
      - is not issued by a CA
      - is unrelated to the certificate generated during Phase 4.1

    The purpose is to determine whether the server accepts an arbitrary
    self-signed client identity during a protected SignAndEncrypt handshake.
    """

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(
            NameOID.COMMON_NAME,
            "independent-untrusted-client",
        ),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(
            now + datetime.timedelta(days=1)
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.UniformResourceIdentifier(application_uri),
            ]),
            critical=False,
        )
        .sign(
            private_key=key,
            algorithm=hashes.SHA256(),
        )
    )

    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(cert_path, "wb") as f:
        f.write(
            certificate.public_bytes(
                serialization.Encoding.PEM,
            )
        )

    return certificate


# ---------------------------------------------------------------------------
# Certificate Inspection
# ---------------------------------------------------------------------------

def inspect_certificate(cert_path: str):
    """
    Print basic certificate properties used for the trust-boundary test.
    """

    with open(cert_path, "rb") as f:
        certificate = x509.load_pem_x509_certificate(f.read())

    console.print("\n[bold cyan]Generated Certificate Properties[/bold cyan]")

    table = Table(header_style="bold magenta")

    table.add_column("Property", style="cyan")
    table.add_column("Value", style="yellow")

    table.add_row(
        "Subject",
        certificate.subject.rfc4514_string(),
    )

    table.add_row(
        "Issuer",
        certificate.issuer.rfc4514_string(),
    )

    table.add_row(
        "Self-Signed",
        str(
            certificate.subject == certificate.issuer
        ),
    )

    table.add_row(
        "Serial Number",
        str(certificate.serial_number),
    )

    table.add_row(
        "Signature Algorithm",
        certificate.signature_hash_algorithm.name,
    )

    try:
        san = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value

        uris = san.get_values_for_type(
            x509.UniformResourceIdentifier
        )

        dns_names = san.get_values_for_type(
            x509.DNSName
        )

        table.add_row(
            "Application URI",
            ", ".join(uris) if uris else "None",
        )

        table.add_row(
            "DNS SAN",
            ", ".join(dns_names) if dns_names else "None",
        )

    except x509.ExtensionNotFound:
        table.add_row(
            "Subject Alternative Name",
            "Not present",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Phase 4.2 — Independent Self-Signed Certificate Test
# ---------------------------------------------------------------------------

async def test_independent_self_signed_certificate():

    console.print(
        "\n[bold cyan]=== X.509 Trust Boundary Retest ===[/bold cyan]"
    )

    console.print(
        "[*] Generating a completely independent self-signed "
        "client certificate..."
    )

    certificate = generate_independent_self_signed_certificate()

    console.print(
        "[+] New RSA keypair generated."
    )

    console.print(
        "[+] Certificate is self-signed."
    )

    console.print(
        f"[+] Application URI: "
        f"[yellow]{TEST_APPLICATION_URI}[/yellow]"
    )

    console.print(
        "[+] Certificate is unrelated to the previous Phase 4 "
        "certificate."
    )

    inspect_certificate(CERT_PATH)

    console.print(
        "\n[*] Attempting protected OPC UA connection:"
    )

    console.print(
        "[*] Security Policy: [yellow]Basic256Sha256[/yellow]"
    )

    console.print(
        "[*] Security Mode: [yellow]SignAndEncrypt[/yellow]"
    )

    client = Client(url=SERVER_URL)

    try:

        await client.set_security_string(
            f"Basic256Sha256,SignAndEncrypt,"
            f"{CERT_PATH},{KEY_PATH}"
        )

        async with client:

            console.print(
                "\n[bold red][OBSERVATION][/bold red] "
                "Server accepted the independently generated "
                "self-signed certificate."
            )

            console.print(
                "[yellow]Result:[/yellow] "
                "The certificate was not rejected during the "
                "observed protected connection attempt."
            )

            console.print(
                "\n[bold yellow]Interpretation:[/bold yellow]"
            )

            console.print(
                "The result increases confidence that the server "
                "does not require this client certificate to chain "
                "to a conventional external CA."
            )

            console.print(
                "[dim]However, this test alone does not establish "
                "whether the certificate was explicitly trusted, "
                "whether the server's trust store permits self-signed "
                "certificates, or whether certificate-based identity "
                "authorization was actually granted.[/dim]"
            )

    except UaError as e:

        error_type = e.__class__.__name__

        console.print(
            "\n[bold green][SECURE BOUNDARY][/bold green] "
            "Server rejected the independent self-signed "
            "certificate."
        )

        console.print(
            f"[*] Protocol Exception: "
            f"[bold yellow]{error_type}[/bold yellow]"
        )

        console.print(
            f"[*] Details: {e}"
        )

        console.print(
            "\n[bold yellow]Interpretation:[/bold yellow]"
        )

        console.print(
            "The server did not accept this independently "
            "generated certificate during the tested handshake."
        )

    except Exception as e:

        console.print(
            "\n[bold yellow][INCONCLUSIVE][/bold yellow] "
            "Connection failed outside the expected OPC UA "
            "certificate validation path."
        )

        console.print(
            f"[*] Exception: {e}"
        )

        console.print(
            "[dim]The failure should be investigated before "
            "classifying the certificate trust boundary.[/dim]"
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main():

    console.print(
        Panel.fit(
            "[bold green]"
            "OPC UA Phase 4.2: Independent X.509 Trust Boundary Test"
            "[/bold green]"
        )
    )

    await test_independent_self_signed_certificate()

    console.save_text(
        "phase4_output_2.txt"
    )

    print(
        "\n[+] Phase 4.2 output saved to phase4_output_2.txt"
    )


if __name__ == "__main__":
    asyncio.run(main())
