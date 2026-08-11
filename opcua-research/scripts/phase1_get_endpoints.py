import asyncio
from asyncua import Client
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

SERVER_URL = "opc.tcp://127.0.0.1:4840"
console = Console()

async def discover_endpoints():
    console.print(f"[bold blue][*][/bold blue] Target Server: [bold cyan]{SERVER_URL}[/bold cyan]")
    console.print("[bold blue][*][/bold blue] Sending unauthenticated [bold yellow]GetEndpointsRequest[/bold yellow] over opc.tcp...")

    try:
        # Establish transport and SecureChannel context
        async with Client(url=SERVER_URL) as client:
            endpoints = await client.get_endpoints()
    except Exception as e:
        console.print(f"[bold red][-] Discovery failed:[/bold red] {e}")
        return

    console.print(f"[bold green][+][/bold green] Received [bold yellow]{len(endpoints)}[/bold yellow] exposed endpoints.\n")

    # Metadata Panel
    if endpoints:
        server_app = endpoints[0].Server
        meta_text = (
            f"[bold white]Application Name:[/bold white] {server_app.ApplicationName.Text}\n"
            f"[bold white]Application URI:[/bold white]  {server_app.ApplicationUri}\n"
            f"[bold white]Product URI:[/bold white]      {server_app.ProductUri}\n"
            f"[bold white]Application Type:[/bold white] {server_app.ApplicationType.name}"
        )
        console.print(Panel(meta_text, title="[bold red]Leaked Server Metadata[/bold red]", expand=False))
        console.print()

    # Endpoints Table
    table = Table(title="Exposed Endpoints & Security Policies", header_style="bold magenta")
    table.add_column("Idx", justify="center", style="dim")
    table.add_column("Endpoint URL", style="cyan")
    table.add_column("Security Mode", justify="center")
    table.add_column("Security Policy", style="yellow")
    table.add_column("Allowed User Tokens", style="green")

    for idx, ep in enumerate(endpoints):
        policy_name = ep.SecurityPolicyUri.split("#")[-1] if "#" in ep.SecurityPolicyUri else ep.SecurityPolicyUri
        mode_name = ep.SecurityMode.name

        if policy_name == "None":
            policy_style = "[bold red]None (UNENCRYPTED)[/bold red]"
            mode_style = f"[bold red]{mode_name}[/bold red]"
        else:
            policy_style = f"[green]{policy_name}[/green]"
            mode_style = f"[green]{mode_name}[/green]"

        user_tokens = []
        for token in ep.UserIdentityTokens:
            token_type = token.TokenType.name
            if token_type == "Anonymous":
                user_tokens.append("[bold red]Anonymous[/bold red]")
            else:
                user_tokens.append(token_type)
        tokens_str = ", ".join(user_tokens) if user_tokens else "None"

        table.add_row(
            str(idx),
            ep.EndpointUrl,
            mode_style,
            policy_style,
            tokens_str
        )

    console.print(table)

if __name__ == "__main__":
    asyncio.run(discover_endpoints())