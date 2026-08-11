import asyncio
from asyncua import Client, ua
from asyncua.ua.uaerrors import UaError
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

# Console configured to record and save output to file
console = Console(record=True)

SERVER_URL = "opc.tcp://127.0.0.1:4840"

ACCESS_LEVEL_READ = 0x01
ACCESS_LEVEL_WRITE = 0x02

def decode_access_level(mask: int) -> str:
    if mask is None:
        return "N/A"
    flags = []
    if mask & ACCESS_LEVEL_READ:
        flags.append("Read")
    if mask & ACCESS_LEVEL_WRITE:
        flags.append("Write")
    if not flags:
        flags.append("None")
    return " | ".join(flags)

def parse_node_id_type(node_id: ua.NodeId) -> str:
    id_type = node_id.NodeIdType
    if id_type == ua.NodeIdType.Numeric:
        return f"Numeric (ns={node_id.NamespaceIndex};i={node_id.Identifier})"
    elif id_type == ua.NodeIdType.String:
        return f"String (ns={node_id.NamespaceIndex};s={node_id.Identifier})"
    elif id_type == ua.NodeIdType.Guid:
        return f"GUID (ns={node_id.NamespaceIndex};g={node_id.Identifier})"
    elif id_type == ua.NodeIdType.ByteString:
        return f"Opaque (ns={node_id.NamespaceIndex};b={node_id.Identifier})"
    return str(node_id)

async def build_node_tree(node, tree_node: Tree, current_depth: int = 0, max_depth: int = 2):
    if current_depth >= max_depth:
        return

    try:
        children = await node.get_children()
        for child in children:
            browse_name = (await child.read_browse_name()).Name
            node_class = (await child.read_node_class()).name
            node_id_str = parse_node_id_type(child.nodeid)
            
            label = f"[bold cyan]{browse_name}[/bold cyan] [dim]({node_class} | {node_id_str})[/dim]"
            sub_tree = tree_node.add(label)
            
            await build_node_tree(child, sub_tree, current_depth + 1, max_depth)
    except Exception as e:
        tree_node.add(f"[red]Error expanding node: {e}[/red]")

async def demonstrate_browse_path_translation(client: Client):
    console.print("\n[bold cyan]=== [1] Translating Browse Paths to NodeIds ===[/bold cyan]")
    
    relative_path = ["0:Objects", "0:Server", "0:ServerStatus", "0:CurrentTime"]
    console.print(f"[*] Resolving relative path: [yellow]{' -> '.join(relative_path)}[/yellow]")
    
    try:
        target_node = await client.nodes.root.get_child(relative_path)
        node_id = target_node.nodeid
        console.print(f"[bold green][+][/bold green] Path resolved successfully!")
        console.print(f"[bold green][+][/bold green] NodeId Type & Address: [bold magenta]{parse_node_id_type(node_id)}[/bold magenta]")
    except Exception as e:
        console.print(f"[bold red][-] Browse path translation failed:[/bold red] {e}")

async def collect_variable_nodes(node, discovered: list, max_depth: int = 3, current_depth: int = 0):
    if current_depth >= max_depth:
        return
    try:
        children = await node.get_children()
        for child in children:
            try:
                n_class = await child.read_node_class()
                if n_class == ua.NodeClass.Variable:
                    if child.nodeid.NamespaceIndex != 0 or "ServerStatus" in str(child.nodeid):
                        discovered.append(child)
                elif n_class == ua.NodeClass.Object:
                    await collect_variable_nodes(child, discovered, max_depth, current_depth + 1)
            except Exception:
                continue
    except Exception:
        pass

async def audit_nodes_and_test_write(client: Client):
    console.print("\n[bold cyan]=== [2] Auditing Discovered Variables & Access Levels ===[/bold cyan]")
    
    var_nodes = []
    await collect_variable_nodes(client.nodes.objects, var_nodes, max_depth=3)

    table = Table(title="Discovered Address Space Variables", header_style="bold magenta")
    table.add_column("Browse Name", style="cyan")
    table.add_column("NodeId", style="magenta")
    table.add_column("AccessLevel", style="green")
    table.add_column("UserAccessLevel", style="red")
    table.add_column("Current Value / Status", style="white")

    testable_variables = []

    for n in var_nodes:
        b_name = "Unknown"
        try:
            b_name = (await n.read_browse_name()).Name
        except Exception:
            pass

        n_id = parse_node_id_type(n.nodeid)

        try:
            acc_level = decode_access_level(await n.read_access_level())
        except Exception:
            acc_level = "Denied"

        try:
            usr_acc_level = decode_access_level(await n.read_user_access_level())
        except Exception:
            usr_acc_level = "Denied"

        try:
            val = await n.read_value()
            val_str = str(val)
            testable_variables.append((n, b_name, val))
        except UaError as e:
            val_str = f"[bold red]<{e.__class__.__name__}>[/bold red]"
        except Exception as e:
            val_str = f"[yellow]<{e.__class__.__name__}>[/yellow]"

        table.add_row(b_name, n_id, acc_level, usr_acc_level, val_str)

    console.print(table)

    console.print("\n[bold cyan]=== [3] Testing Write Execution & Authorization Enforcement ===[/bold cyan]")
    if not testable_variables:
        console.print("[yellow][!] No testable variable nodes discovered for write operations.[/yellow]")
        return

    for node, name, current_val in testable_variables:
        console.print(f"[*] Testing Write access on tag [bold cyan]{name}[/bold cyan] ({node.nodeid})...")
        
        if isinstance(current_val, bool):
            test_val = not current_val
        elif isinstance(current_val, int):
            test_val = current_val + 1
        elif isinstance(current_val, float):
            test_val = current_val + 1.0
        elif isinstance(current_val, str):
            test_val = current_val + "_probe"
        elif isinstance(current_val, bytes):
            test_val = current_val + b"_probe"
        else:
            console.print("    [dim]Skipping complex type write test.[/dim]")
            continue

        try:
            await node.write_value(test_val)
            console.print(
                f"    [bold red][CRITICAL VULNERABILITY][/bold red] Write ACCEPTED on tag [bold cyan]{name}[/bold cyan]! "
                f"Value changed: {current_val} -> {test_val}"
            )
            # Revert write if successful
            await node.write_value(current_val)
            console.print("    [dim]Reverted test value back to original state.[/dim]")
        except UaError as e:
            error_type = e.__class__.__name__
            if "BadNotWritable" in str(e) or "BadUserAccessDenied" in str(e) or error_type in ["BadNotWritable", "BadUserAccessDenied"]:
                console.print(f"    [bold green][SECURE][/bold green] Write rejected by server authorization: [yellow]{e}[/yellow]")
            else:
                console.print(f"    [bold yellow][REJECTED][/bold yellow] OPC UA Protocol Error ({error_type}): {e}")
        except Exception as e:
            console.print(f"    [bold red][-][/bold red] Write operation failed: {e}")

async def main():
    console.print(Panel.fit("[bold green]OPC UA Phase 3: Address Space & Information Model Reconnaissance[/bold green]"))
    
    client = Client(url=SERVER_URL)
    
    try:
        async with client:
            await demonstrate_browse_path_translation(client)
            
            console.print("\n[bold cyan]=== [2] Crawling Object Graph (Root -> Objects) ===[/bold cyan]")
            tree = Tree("[bold magenta]Root (ns=0;i=84)[/bold magenta]")
            await build_node_tree(client.nodes.objects, tree, current_depth=0, max_depth=2)
            console.print(tree)
            
            await audit_nodes_and_test_write(client)

    except Exception as e:
        console.print(f"[bold red][-] Client Connection Failure:[/bold red] {e}")
    finally:
        # Save complete formatted terminal log to file
        console.save_text("phase3_output.txt")
        print("\n[+] Full output log saved to phase3_output.txt")

if __name__ == "__main__":
    asyncio.run(main())