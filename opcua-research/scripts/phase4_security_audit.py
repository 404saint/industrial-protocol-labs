import asyncio
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from asyncua import Client, ua
from asyncua.ua.uaerrors import UaError

from rich.console import Console
from rich.panel import Panel
from rich.table import Table


console = Console(record=True)

SERVER_URL = "opc.tcp://127.0.0.1:4840"

CERT_PATH = "untrusted_cert.pem"
KEY_PATH = "untrusted_key.pem"


# ---------------------------------------------------------------------------
# Certificate Generation
# ---------------------------------------------------------------------------

def generate_untrusted_cert(
    cert_path: str = CERT_PATH,
    key_path: str = KEY_PATH,
    application_uri: str = "urn:freeopcua:client",
):
    """
    Generate a self-signed client certificate.

    The Application URI is deliberately aligned with the client identity so
    that certificate rejection cannot simply be attributed to an
    ApplicationDescription URI mismatch.
    """

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(
            NameOID.COMMON_NAME,
            "untrusted.client",
        ),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
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
            cert.public_bytes(
                serialization.Encoding.PEM,
            )
        )

    return application_uri


# ---------------------------------------------------------------------------
# Phase 4.1 — Security Policy Exposure
# ---------------------------------------------------------------------------

async def analyze_security_policy_exposure():

    console.print(
        "\n[bold cyan]=== [1] Security Policy Exposure Analysis ===[/bold cyan]"
    )

    client = Client(url=SERVER_URL)

    try:
        endpoints = await client.connect_and_get_server_endpoints()

        table = Table(
            title="Advertised Server Endpoints",
            header_style="bold magenta",
        )

        table.add_column("Index", justify="center")
        table.add_column("Endpoint URL", style="cyan")
        table.add_column("Security Mode", style="green")
        table.add_column("Security Policy", style="yellow")
        table.add_column("Transport Profile", style="white")

        insecure_endpoint = False
        secure_endpoint_count = 0

        for index, ep in enumerate(endpoints):

            sec_mode = ua.MessageSecurityMode(ep.SecurityMode).name

            sec_policy = ep.SecurityPolicyUri.split("#")[-1]

            transport_profile = ep.TransportProfileUri.split("/")[-1]

            if sec_mode == "None_" and sec_policy == "None":
                insecure_endpoint = True

                sec_mode_display = (
                    f"[bold red]{sec_mode}[/bold red]"
                )

                sec_policy_display = (
                    f"[bold red]{sec_policy}[/bold red]"
                )

            else:
                secure_endpoint_count += 1

                sec_mode_display = sec_mode
                sec_policy_display = sec_policy

            table.add_row(
                str(index),
                ep.EndpointUrl,
                sec_mode_display,
                sec_policy_display,
                transport_profile,
            )

        console.print(table)

        console.print(
            f"\n[*] Secure endpoints discovered: "
            f"[bold]{secure_endpoint_count}[/bold]"
        )

        if insecure_endpoint:

            console.print(
                "\n[bold red][VULNERABLE][/bold red] "
                "The server advertises a SecurityPolicy#None endpoint "
                "alongside cryptographically protected endpoints."
            )

            console.print(
                "[yellow]Observation:[/yellow] "
                "An unauthenticated client can select the plaintext endpoint "
                "during endpoint selection."
            )

            console.print(
                "[dim]This test establishes insecure endpoint exposure; "
                "it does not demonstrate an active protocol downgrade attack.[/dim]"
            )

        else:

            console.print(
                "\n[bold green][SECURE][/bold green] "
                "No SecurityPolicy#None endpoint was advertised."
            )

    except Exception as e:

        console.print(
            f"[bold red][-] Endpoint analysis failed:[/bold red] {e}"
        )


# ---------------------------------------------------------------------------
# Phase 4.2 — Certificate Validation
# ---------------------------------------------------------------------------

async def test_untrusted_certificate():

    console.print(
        "\n[bold cyan]=== [2] X.509 Certificate Validation Audit ===[/bold cyan]"
    )

    client = Client(url=SERVER_URL)

    # asyncua's default application URI is used so the certificate identity
    # matches the ApplicationDescription presented by the client.
    application_uri = getattr(
        client,
        "application_uri",
        "urn:freeopcua:client",
    )

    console.print(
        f"[*] Client Application URI: [yellow]{application_uri}[/yellow]"
    )

    generate_untrusted_cert(
        CERT_PATH,
        KEY_PATH,
        application_uri=application_uri,
    )

    console.print(
        "[*] Generated self-signed client certificate."
    )

    console.print(
        "[*] Certificate SAN contains the matching Application URI."
    )

    console.print(
        "[*] Attempting Basic256Sha256 / SignAndEncrypt connection..."
    )

    try:

        await client.set_security_string(
            f"Basic256Sha256,SignAndEncrypt,{CERT_PATH},{KEY_PATH}"
        )

        async with client:

            console.print(
                "\n[bold red][VULNERABLE][/bold red] "
                "Server accepted the self-signed client certificate."
            )

            console.print(
                "[yellow]Observation:[/yellow] "
                "The test certificate was not rejected during the "
                "observed connection attempt."
            )

            console.print(
                "[dim]Further trust-store analysis would be required to "
                "determine whether the server intentionally trusts "
                "self-signed client certificates.[/dim]"
            )

    except UaError as e:

        error_type = e.__class__.__name__

        console.print(
            "\n[bold green][SECURE][/bold green] "
            "Server rejected the certificate during the handshake."
        )

        console.print(
            f"[*] Protocol Exception: "
            f"[bold yellow]{error_type}[/bold yellow]"
        )

        console.print(
            f"[*] Details: {e}"
        )

    except Exception as e:

        console.print(
            "\n[bold yellow][REJECTED][/bold yellow] "
            "Connection failed during certificate validation."
        )

        console.print(
            f"[*] Exception: {e}"
        )


# ---------------------------------------------------------------------------
# Phase 4.3 — Identity Authentication Boundary
# ---------------------------------------------------------------------------

async def test_invalid_identity():

    console.print(
        "\n[bold cyan]=== [3] Invalid Identity Authentication Audit ===[/bold cyan]"
    )

    bad_user = "admin_probe"
    bad_pass = "invalid_password_123"

    console.print(
        f"[*] Attempting authentication with invalid credentials: "
        f"[yellow]{bad_user}[/yellow]"
    )

    client = Client(url=SERVER_URL)

    client.set_user(bad_user)
    client.set_password(bad_pass)

    try:

        async with client:

            console.print(
                "\n[bold red][VULNERABLE][/bold red] "
                "Session establishment succeeded with invalid credentials."
            )

            console.print(
                "[yellow]Observation:[/yellow] "
                "The configured identity provider did not reject the "
                "supplied credentials."
            )

    except UaError as e:

        error_type = e.__class__.__name__

        console.print(
            "\n[bold green][SECURE][/bold green] "
            "Invalid credentials were rejected."
        )

        console.print(
            f"[*] Protocol Exception: "
            f"[bold yellow]{error_type}[/bold yellow]"
        )

        console.print(
            f"[*] Details: {e}"
        )

    except Exception as e:

        console.print(
            "\n[bold yellow][?][/bold yellow] "
            "Unexpected authentication failure."
        )

        console.print(
            f"[*] Exception: {e}"
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main():

    console.print(
        Panel.fit(
            "[bold green]OPC UA Phase 4: "
            "Security Boundaries & Misconfiguration Audit[/bold green]"
        )
    )

    await analyze_security_policy_exposure()

    await test_untrusted_certificate()

    await test_invalid_identity()

    console.save_text("phase4_output.txt")

    print(
        "\n[+] Complete Phase 4 audit log saved to phase4_output.txt"
    )


if __name__ == "__main__":
    asyncio.run(main())