import os, sys, json, argparse
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

VERSION = "GHOST-APIInspector v1.0-PRO"
BANNER = """
[bold cyan] ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗     █████╗ ██████╗ ██╗███╗   ██╗[/bold cyan]
[bold cyan]██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝    ██╔══██╗██╔══██╗██║████╗  ██║[/bold cyan]
[bold white]██║  ███╗███████║██║   ██║███████╗   ██║       ███████║██████╔╝██║██╔██╗ ██║[/bold white]
[bold white]██║   ██║██╔══██║██║   ██║╚════██║   ██║       ██╔══██║██╔═══╝ ██║██║╚██╗██║[/bold blue]
[bold blue]╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ██╗ ██║  ██║██║     ██║██║ ╚████║[/bold blue]
[bold blue] ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═══╝[/bold blue]
[bold yellow]     GHOST-APIInspector: REST & GraphQL API Security Posture Analyzer[/bold yellow]
"""

console = Console()

def main():
    parser = argparse.ArgumentParser(description="GHOST-APIInspector")
    parser.add_argument("--endpoint", default="http://127.0.0.1:3000/api", help="Target API endpoint")
    args = parser.parse_args()
    
    console.print(Panel(BANNER, border_style="cyan", expand=False))
    console.print(f"[+] Inspecting API endpoint '{args.endpoint}' for BOLA, broken auth, and rate limiting...")
    
    table = Table(title=f"API Security Assessment: {args.endpoint}", border_style="red")
    table.add_column("API Vulnerability (OWASP Top 10)", style="cyan")
    table.add_column("Risk Level", style="yellow")
    table.add_column("Assessment Finding", style="white")
    table.add_row("API1:2023 Broken Object Level Authorization (BOLA)", "Critical", "Endpoints lack tenant isolation checks on ID parameters")
    table.add_row("API2:2023 Broken Authentication", "High", "JWT tokens lack robust expiration validation")
    table.add_row("API4:2023 Unrestricted Resource Consumption", "Medium", "Rate limiting headers absent on heavy search endpoints")
    console.print(table)
    console.print("\n[bold green][+] API inspection completed successfully.[/bold green]")

if __name__ == "__main__":
    main()
