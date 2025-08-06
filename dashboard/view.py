#!/usr/bin/env python3
"""
CLI Dashboard for displaying infected hosts from loot/infected.jsonl
"""

import json
import os
import sys
from datetime import datetime
from typing import List, Dict, Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text


def render_dashboard() -> None:
    """
    Render the CLI dashboard displaying infected hosts from loot/infected.jsonl
    """
    console = Console()
    
    # Define the file path
    loot_file = "loot/infected.jsonl"
    
    # Check if file exists
    if not os.path.exists(loot_file):
        console.print(
            Panel(
                Text(f"File not found: {loot_file}", style="bold red"),
                title="Error",
                border_style="red"
            )
        )
        return
    
    # Read and parse the JSONL file
    infected_entries: List[Dict[str, Any]] = []
    
    try:
        with open(loot_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    infected_entries.append(entry)
                except json.JSONDecodeError as e:
                    console.print(
                        f"[yellow]Warning: Invalid JSON on line {line_num}: {e}[/yellow]"
                    )
    except Exception as e:
        console.print(
            Panel(
                Text(f"Error reading file: {e}", style="bold red"),
                title="Error",
                border_style="red"
            )
        )
        return
    
    if not infected_entries:
        console.print(
            Panel(
                Text("No infected entries found in the file", style="yellow"),
                title="Empty File",
                border_style="yellow"
            )
        )
        return
    
    # Create the table
    table = Table(title="Infected Hosts Dashboard", show_header=True, header_style="bold magenta")
    
    # Add columns
    table.add_column("#", style="cyan", width=4, justify="right")
    table.add_column("IP Address", style="green", width=15)
    table.add_column("Hostname", style="blue", width=20)
    table.add_column("User", style="yellow", width=15)
    table.add_column("Module", style="magenta", width=20)
    table.add_column("Time", style="white", width=16)
    
    # Process each entry and add to table
    unique_hosts = set()
    
    for idx, entry in enumerate(infected_entries, 1):
        # Extract fields with defaults
        host = entry.get('host', 'N/A')
        hostname = entry.get('hostname', 'N/A')
        user = entry.get('user', 'N/A')
        module = entry.get('module', 'N/A')
        timestamp = entry.get('timestamp', '')
        
        # Format timestamp
        formatted_time = "N/A"
        if timestamp:
            try:
                # Handle different timestamp formats
                if isinstance(timestamp, (int, float)):
                    # Unix timestamp
                    dt = datetime.fromtimestamp(timestamp)
                elif isinstance(timestamp, str):
                    # Try parsing ISO format
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                else:
                    dt = datetime.fromtimestamp(timestamp)
                
                formatted_time = dt.strftime("%Y-%m-%d %H:%M")
            except (ValueError, TypeError):
                formatted_time = str(timestamp)
        
        # Add to unique hosts
        unique_hosts.add(host)
        
        # Add row to table
        table.add_row(
            str(idx),
            str(host),
            str(hostname),
            str(user),
            str(module),
            formatted_time
        )
    
    # Display the table
    console.print(table)
    
    # Display summary
    total_infected = len(infected_entries)
    unique_hosts_count = len(unique_hosts)
    
    summary_text = f"""
[bold green]Total Infected:[/bold green] {total_infected}
[bold blue]Unique Hosts:[/bold blue] {unique_hosts_count}
"""
    
    console.print(
        Panel(
            Text.from_markup(summary_text),
            title="Summary",
            border_style="green"
        )
    )


if __name__ == "__main__":
    render_dashboard()
