#!/usr/bin/env python3
import ctypes
import os
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich import print as rprint

console = Console()

LIB_PATH = "/home/tesla/Desktop/iec61850-lab/libiec61850/build/src/libiec61850.so"

if not os.path.exists(LIB_PATH):
    console.print(f"[bold red][-] Shared library not found at {LIB_PATH}.[/bold red]")
    sys.exit(1)

iec61850 = ctypes.CDLL(LIB_PATH)
TARGET_IP = b"192.168.1.10"
TARGET_PORT = 102

# Helper setup for libiec61850 LinkedList
iec61850.LinkedList_getNext.argtypes = [ctypes.c_void_p]
iec61850.LinkedList_getNext.restype = ctypes.c_void_p

iec61850.LinkedList_getData.argtypes = [ctypes.c_void_p]
iec61850.LinkedList_getData.restype = ctypes.c_void_p

iec61850.LinkedList_destroy.argtypes = [ctypes.c_void_p]


def run():
    console.print(
        Panel.fit(
            "[bold cyan]Phase 2: Plaintext MMS Session State & Substation Namespace Enumeration[/bold cyan]\n"
            "[dim]ISO 8073 (COTP) | ISO 8327 (Session) | ASN.1 BER MMS Payloads[/dim]",
            border_style="cyan",
        )
    )

    # 1. Create MMS Connection Handle
    iec61850.MmsConnection_create.restype = ctypes.c_void_p
    con = iec61850.MmsConnection_create()

    iec61850.MmsConnection_connect.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_int,
    ]
    iec61850.MmsConnection_connect.restype = ctypes.c_int

    err = ctypes.c_int()

    # 2. Connection Phase
    with console.status("[bold green]Establishing TPKT/COTP & MMS Initiate-Request...", spinner="dots"):
        success = iec61850.MmsConnection_connect(
            con, ctypes.byref(err), TARGET_IP, TARGET_PORT
        )

    if success != 1:
        console.print(f"[bold red][-] MMS Association Failed. Error Code: {err.value}[/bold red]")
        iec61850.MmsConnection_destroy(con)
        return

    console.print("[bold green][+] Status: MMS Session & Application Association Established![/bold green]\n")

    # 3. Domain Enumeration (VMD Level)
    iec61850.MmsConnection_getDomainNames.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    iec61850.MmsConnection_getDomainNames.restype = ctypes.c_void_p

    domain_list = iec61850.MmsConnection_getDomainNames(con, ctypes.byref(err))

    domains = []
    if domain_list:
        curr = domain_list
        while curr:
            data_ptr = iec61850.LinkedList_getData(curr)
            if data_ptr:
                val = ctypes.cast(data_ptr, ctypes.c_char_p).value
                if val:
                    domains.append(val.decode("utf-8"))
            curr = iec61850.LinkedList_getNext(curr)

        # Build visual tree representation for screenshot
        tree = Tree(f"[bold yellow]IED: {TARGET_IP.decode()}:{TARGET_PORT}[/bold yellow]")

        iec61850.MmsConnection_getDomainVariableNames.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_char_p,
        ]
        iec61850.MmsConnection_getDomainVariableNames.restype = ctypes.c_void_p

        # 4. Object Enumeration per Domain with Truncation Limit
        DISPLAY_LIMIT = 8

        for domain in domains:
            domain_node = tree.add(f"[bold magenta]Domain (Logical Device): {domain}[/bold magenta]")
            var_list = iec61850.MmsConnection_getDomainVariableNames(
                con, ctypes.byref(err), domain.encode("utf-8")
            )

            if var_list:
                objects = []
                curr_var = var_list
                while curr_var:
                    data_ptr = iec61850.LinkedList_getData(curr_var)
                    if data_ptr:
                        val = ctypes.cast(data_ptr, ctypes.c_char_p).value
                        if val:
                            objects.append(val.decode("utf-8", errors="ignore"))
                    curr_var = iec61850.LinkedList_getNext(curr_var)

                total_count = len(objects)

                # Show first N objects
                for obj in objects[:DISPLAY_LIMIT]:
                    domain_node.add(f"[green]{obj}[/green]")

                # Truncate view if higher than DISPLAY_LIMIT
                if total_count > DISPLAY_LIMIT:
                    domain_node.add(
                        f"[dim yellow]... {total_count - DISPLAY_LIMIT} more MMS variables hidden (Total Enumerated: {total_count})[/dim yellow]"
                    )
                else:
                    domain_node.add(f"[dim blue](Total Enumerated: {total_count})[/dim blue]")

                iec61850.LinkedList_destroy(var_list)
            else:
                domain_node.add(f"[red]Failed to retrieve variables (Err: {err.value})[/red]")

        console.print(tree)
        iec61850.LinkedList_destroy(domain_list)
    else:
        console.print(f"[bold red][-] GetDomainNames failed. Error Code: {err.value}[/bold red]")

    # 5. Teardown
    iec61850.MmsConnection_close.argtypes = [ctypes.c_void_p]
    iec61850.MmsConnection_close(con)
    iec61850.MmsConnection_destroy(con)

    console.print("\n[bold cyan][+] Phase 2 Namespace Mapping Complete.[/bold cyan]")


if __name__ == "__main__":
    run()