"""Shared utilities for all demo scripts."""

import os
import json
import time
import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

BASE_URL = os.environ.get("TARGET_URL", "http://localhost:8000")
console = Console()


def send(message: str, endpoint: str = "/chat/debug") -> dict:
    """Send a message and return the parsed JSON response."""
    try:
        r = requests.post(
            f"{BASE_URL}{endpoint}",
            json={"message": message, "max_tokens": 200},
            timeout=30,
        )
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        console.print(f"[bold red]ERROR: Cannot connect to {BASE_URL}[/bold red]")
        console.print("Make sure the llm-server is running: docker compose up llm-server")
        raise SystemExit(1)


def reset():
    requests.post(f"{BASE_URL}/reset", timeout=5)


def print_attack(title: str, payload: str, result: dict, expected_success: bool = True):
    """Pretty-print an attack attempt and its result."""
    leaked = "INJECTION SUCCESSFUL" in result.get("response", "") or \
             "FLAG{" in result.get("response", "")

    status = "[bold green]ATTACK SUCCEEDED[/bold green]" if leaked else \
             "[bold red]ATTACK BLOCKED[/bold red]"

    if result.get("filter_triggered"):
        status = "[yellow]FILTER TRIGGERED (blocked by keyword filter)[/yellow]"

    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_row("[cyan]Payload[/cyan]", repr(payload))
    table.add_row("[cyan]Filter triggered[/cyan]", str(result.get("filter_triggered")))
    table.add_row("[cyan]Status[/cyan]", status)
    table.add_row("[cyan]Response[/cyan]", result.get("response", "")[:300])

    console.print(Panel(table, title=f"[bold magenta]{title}[/bold magenta]", expand=False))
    time.sleep(0.3)
    return leaked


def section(title: str):
    console.rule(f"[bold blue]{title}[/bold blue]")
