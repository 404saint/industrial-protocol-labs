import asyncio

from asyncua import Client
from asyncua.ua.uaerrors import BadUserAccessDenied, UaError
from rich.console import Console
from rich.panel import Panel
from rich.table import Table


SERVER_URL = "opc.tcp://127.0.0.1:4840"

console = Console()


def safe_get_channel_id(client: Client) -> str:
    """Safely extract the SecureChannel ID across asyncua versions."""
    try:
        uaclient = getattr(client, "uaclient", None)

        if uaclient:
            channel = getattr(uaclient, "channel", None)

            if channel:
                security_token = getattr(channel, "security_token", None)

                if security_token:
                    channel_id = getattr(security_token, "ChannelId", None)

                    if channel_id is not None:
                        return str(channel_id)

            connection = getattr(uaclient, "_connection", None)

            if connection:
                channel_id = getattr(connection, "channel_id", None)

                if channel_id is not None:
                    return str(channel_id)

        return "Established"

    except Exception:
        return "Established"


def safe_get_session_id(client: Client) -> str:
    """
    Attempt to retrieve the Session NodeId without assuming
    that asyncua exposes client.session publicly.
    """
    try:
        uaclient = getattr(client, "uaclient", None)

        if uaclient:
            session = getattr(uaclient, "session", None)

            if session:
                node_id = getattr(session, "NodeId", None)

                if node_id:
                    return str(node_id)

                node_id = getattr(session, "nodeid", None)

                if node_id:
                    return str(node_id)

        # Some asyncua versions expose the session through the
        # internal session object differently. The important
        # success criterion remains successful connect().
        return "Established"

    except Exception:
        return "Established"


async def test_anonymous_handshake():
    console.print(
        "\n[bold cyan]"
        "=== [1] Testing Anonymous Session Handshake "
        "(SecurityPolicy#None) ==="
        "[/bold cyan]"
    )

    client = Client(url=SERVER_URL)

    try:
        console.print(
            "[bold blue][*][/bold blue] Executing "
            "[bold yellow]OpenSecureChannel[/bold yellow], "
            "[bold yellow]CreateSession[/bold yellow], and "
            "[bold yellow]ActivateSession (Anonymous)[/bold yellow]..."
        )

        # No username/password configured.
        # asyncua will use the server's available anonymous
        # identity-token policy if supported.
        await client.connect()

        channel_id = safe_get_channel_id(client)
        session_id = safe_get_session_id(client)

        console.print(
            "[bold green][+][/bold green] SecureChannel established. "
            f"Channel ID: [bold magenta]{channel_id}[/bold magenta]"
        )

        console.print(
            "[bold green][+][/bold green] Session activation succeeded. "
            f"Session: [bold magenta]{session_id}[/bold magenta]"
        )

        table = Table(
            title="Activated Anonymous Session Context",
            header_style="bold magenta",
        )

        table.add_column("Parameter", style="cyan")
        table.add_column("Value / Representation", style="yellow")

        table.add_row(
            "SecureChannel State",
            "OPEN (SecurityPolicy#None)",
        )

        table.add_row(
            "Session State",
            "[bold green]ACTIVE[/bold green]",
        )

        table.add_row(
            "Session NodeID",
            str(session_id),
        )

        session_timeout = getattr(client, "session_timeout", None)

        table.add_row(
            "Session Timeout",
            f"{session_timeout} ms"
            if session_timeout is not None
            else "Negotiated / unavailable",
        )

        table.add_row(
            "Authentication Type",
            "[bold red]Anonymous (UserTokenType: 0)[/bold red]",
        )

        console.print(table)

        console.print(
            "\n[bold yellow][!] Phase 2 Observation:[/bold yellow] "
            "The server accepted an anonymous session over the "
            "SecurityPolicy#None endpoint."
        )

        return True

    except BadUserAccessDenied:
        console.print(
            "[bold red][-] Anonymous session rejected:[/bold red] "
            "BadUserAccessDenied"
        )
        return False

    except UaError as e:
        console.print(
            f"[bold red][-] OPC UA Protocol Error:[/bold red] {e}"
        )
        return False

    except Exception as e:
        console.print(
            f"[bold red][-] Anonymous Handshake Failed:[/bold red] {e}"
        )
        return False

    finally:
        console.print(
            "[bold blue][*][/bold blue] Closing "
            "Session & SecureChannel (`opc.tcp` CLO)..."
        )

        try:
            await client.disconnect()
        except Exception as e:
            console.print(
                f"[dim]Cleanup notice: {e}[/dim]"
            )


async def test_username_handshake(
    username: str = "admin",
    password: str = "secret_pass",
):
    console.print(
        f"\n[bold cyan]"
        f"=== [2] Testing User Identity Token Handshake "
        f"(UserName: {username}) ==="
        f"[/bold cyan]"
    )

    client = Client(url=SERVER_URL)

    client.set_user(username)
    client.set_password(password)

    try:
        console.print(
            "[bold blue][*][/bold blue] Transmitting "
            "[bold yellow]ActivateSessionRequest[/bold yellow] "
            "with UserName Identity Token..."
        )

        await client.connect()

        session_id = safe_get_session_id(client)

        console.print(
            "[bold green][+][/bold green] Session activation succeeded "
            f"for user: [bold green]{username}[/bold green]"
        )

        console.print(
            f"[bold green][+] Session: "
            f"[bold magenta]{session_id}[/bold magenta][/bold green]"
        )

        table = Table(
            title="Activated UserName Session Context",
            header_style="bold magenta",
        )

        table.add_column("Parameter", style="cyan")
        table.add_column("Value / Representation", style="yellow")

        table.add_row(
            "Authentication Type",
            "UserName Identity Token",
        )

        table.add_row(
            "Username",
            username,
        )

        table.add_row(
            "Session State",
            "[bold green]ACTIVE[/bold green]",
        )

        table.add_row(
            "SecureChannel Policy",
            "SecurityPolicy#None",
        )

        console.print(table)

        console.print(
            "\n[bold yellow][!] Observation:[/bold yellow] "
            "The server accepted the supplied UserName credentials."
        )

        console.print(
            "[bold yellow][!] PCAP Verification Required:[/bold yellow] "
            "Inspect the ActivateSessionRequest to determine whether "
            "the UserNameIdentityToken credentials are recoverable "
            "from the captured network traffic."
        )

        return True

    except BadUserAccessDenied:
        console.print(
            "\n[bold yellow][!] Server Response:[/bold yellow] "
            "[bold red]BadUserAccessDenied (0x801F0000)[/bold red]"
        )

        console.print(
            "[bold yellow][!] Authentication Result:[/bold yellow] "
            "The server rejected the supplied credentials."
        )

        console.print(
            "[bold yellow][!] PCAP Verification Required:[/bold yellow] "
            "Because this test uses SecurityPolicy#None, inspect the "
            "captured ActivateSessionRequest to determine whether the "
            "UserNameIdentityToken username and password are exposed "
            "directly on the wire."
        )

        return False

    except UaError as e:
        console.print(
            f"[bold red][-] OPC UA Protocol Error:[/bold red] {e}"
        )
        return False

    except Exception as e:
        console.print(
            f"[bold red][-] Unexpected Handshake Failure:[/bold red] {e}"
        )
        return False

    finally:
        try:
            await client.disconnect()
        except Exception as e:
            console.print(
                f"[dim]Cleanup notice: {e}[/dim]"
            )


async def main():
    console.print(
        Panel.fit(
            "[bold green]"
            "OPC UA Phase 2: SecureChannel & Session State Machine Lab"
            "[/bold green]"
        )
    )

    # ---------------------------------------------------------
    # Test 1: Anonymous Session
    # ---------------------------------------------------------
    anonymous_success = await test_anonymous_handshake()

    # ---------------------------------------------------------
    # Test 2: UserName Identity Token
    # ---------------------------------------------------------
    username_success = await test_username_handshake(
        username="admin",
        password="secret_pass",
    )

    # ---------------------------------------------------------
    # Phase 2 Summary
    # ---------------------------------------------------------
    console.print(
        "\n[bold cyan]=== Phase 2 Test Summary ===[/bold cyan]"
    )

    summary = Table(header_style="bold magenta")

    summary.add_column("Test")
    summary.add_column("Result")
    summary.add_column("Evidence Required")

    summary.add_row(
        "Anonymous Session",
        (
            "[green]SUCCESS[/green]"
            if anonymous_success
            else "[red]REJECTED / FAILED[/red]"
        ),
        "Server response / session state",
    )

    summary.add_row(
        "UserName Authentication",
        (
            "[green]SUCCESS[/green]"
            if username_success
            else "[yellow]REJECTED[/yellow]"
        ),
        "ActivateSession PCAP",
    )

    console.print(summary)


if __name__ == "__main__":
    asyncio.run(main())