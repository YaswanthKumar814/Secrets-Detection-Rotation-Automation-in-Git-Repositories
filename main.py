#!/usr/bin/env python3
"""GitGuard — Hybrid Git Secrets Detection & Mock Rotation System.

Usage:
    python main.py scan <path>                    Scan a local repo for secrets
    python main.py scan-remote <repo_url>         Clone and scan a remote repo (allowlist required)
    python main.py scan-targets <targets.yaml>    Batch scan configured targets
    python main.py history-scan <path>            Scan Git commit history for leaks
    python main.py monitor <path>                 Watch a repo for changes in real-time
    python main.py report                         Generate an HTML executive report
    python main.py aws-check                      Test AWS / LocalStack connectivity
    python main.py dashboard                      Launch the SOC-style web dashboard
    python main.py generate-test-repo             Create a demo repo with fake secrets
"""

import sys
import os
import time

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

BANNER = r"""
   ██████╗ ██╗████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ██╔════╝ ██║╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██║  ███╗██║   ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██║   ██║██║   ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ╚██████╔╝██║   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
   ╚═════╝ ╚═╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
  Hybrid Git Secrets Detection & Mock Rotation
"""


def _print_findings_table(findings: list[dict], title: str = "Scan Results"):
    """Render a findings table shared by scan commands."""
    if not findings:
        console.print("[green]✓ No secrets detected — repository is clean![/green]")
        return

    table = Table(title=title, box=box.ROUNDED, show_lines=True, border_style="cyan")
    table.add_column("Severity", style="bold")
    table.add_column("Type")
    table.add_column("File")
    table.add_column("Conf.", justify="center")
    table.add_column("Preview")
    table.add_column("Score", justify="right")
    table.add_column("Cnt", justify="right")

    sev_colors = {"Critical": "red", "High": "yellow", "Medium": "cyan", "Low": "dim"}
    for f in findings:
        c = sev_colors.get(f["severity"], "white")
        occ = f.get("occurrence_count", 1)
        file_disp = os.path.basename(f["file_path"].split(" (+")[0])
        if occ > 1:
            file_disp += f" [×{occ}]"
        table.add_row(
            f"[{c}]{f['severity']}[/{c}]",
            f["secret_type"][:28],
            file_disp,
            f.get("confidence_label", "—")[:4],
            f["masked_preview"],
            str(f["severity_score"]),
            str(occ) if occ > 1 else "",
        )
    console.print(table)


def _print_history_table(results: list[dict]):
    """Render history scan results."""
    if not results:
        console.print("[green]✓ No historical leaks found.[/green]")
        return

    table = Table(title="History Leaks", box=box.ROUNDED, border_style="yellow")
    table.add_column("Commit", style="cyan")
    table.add_column("Author")
    table.add_column("File")
    table.add_column("Type")
    table.add_column("Severity", style="bold")

    for r in results:
        c = "red" if r["severity"] == "Critical" else "yellow" if r["severity"] == "High" else "cyan"
        table.add_row(
            r["commit_hash"][:8],
            r["author"],
            os.path.basename(r["file_path"]),
            r["secret_type"],
            f"[{c}]{r['severity']}[/{c}]",
        )
    console.print(table)


def _print_s3_export_status(export_result: dict):
    """Accurate S3 export messaging for the report command."""
    from cloud_export.export import describe_s3_export_result

    described = describe_s3_export_result(export_result)
    level = described["level"]
    message = described["message"]
    if level == "success":
        console.print(f"[green]✓ {message}[/green]")
    elif level == "warning":
        console.print(f"[yellow]⚠ {message}[/yellow]")
    else:
        console.print(f"[dim]ℹ {message}[/dim]")


def _print_aws_export_summary(export_result: dict):
    """Show optional AWS export results in the CLI."""
    if export_result.get("warning"):
        console.print(f"[yellow]⚠ AWS:[/yellow] {export_result['warning']}")
        return
    if export_result.get("skipped"):
        return
    if export_result.get("s3_report"):
        console.print(f"[dim]AWS S3 report:[/dim] {export_result['s3_report']}")
    if export_result.get("s3_findings"):
        console.print(f"[dim]AWS S3 findings:[/dim] {export_result['s3_findings']}")
    if export_result.get("sns_alerts"):
        console.print(f"[green]✓ SNS alerts sent:[/green] {export_result['sns_alerts']}")
    if export_result.get("dynamodb_synced"):
        console.print(f"[green]✓ DynamoDB records synced:[/green] {export_result['dynamodb_synced']}")
    if export_result.get("error"):
        console.print(f"[yellow]AWS export warning:[/yellow] {export_result['error']}")


def show_help():
    console.print(Panel(BANNER, style="bold cyan", border_style="cyan"))
    console.print(__doc__, style="dim")


def cmd_scan(path: str):
    """Scan a local repository for secrets."""
    from database import Database
    from scanner import scan_repository
    from rotation import bulk_rotate_critical
    from scanner.repo_ingestion import Allowlist
    from config import ENFORCE_ALLOWLIST_ON_LOCAL_SCAN
    from utils.logger import set_db

    path = os.path.abspath(path)
    if not os.path.isdir(path):
        console.print(f"[red]Error:[/red] '{path}' is not a directory.")
        sys.exit(1)

    if ENFORCE_ALLOWLIST_ON_LOCAL_SCAN:
        allowlist = Allowlist.load_default()
        passed, reason = allowlist.validate_local(path)
        if not passed:
            console.print(f"[red]Allowlist rejected:[/red] {reason}")
            console.print("[dim]Set GITGUARD_ENFORCE_ALLOWLIST=false to skip local allowlist checks.[/dim]")
            sys.exit(1)
        console.print(f"[green]✓ Allowlist check passed:[/green] {reason}")

    console.print(Panel(BANNER, style="bold cyan", border_style="cyan"))
    db = Database()
    set_db(db)

    console.print(f"\n[bold cyan]Scanning:[/bold cyan] {path}\n")
    result = scan_repository(path, db)
    findings = result["findings"]

    db.add_log("INFO", "scanner", f"Scan complete: {len(findings)} findings in {path}")

    _print_findings_table(findings)

    crit = [f for f in findings if f["severity"] == "Critical"]
    if crit:
        console.print(f"\n[bold red]⚠ {len(crit)} CRITICAL secrets found — triggering mock rotation...[/bold red]")
        rotations = bulk_rotate_critical(db)
        console.print(f"[green]✓ {len(rotations)} credentials rotated (mock)[/green]")

    try:
        from cloud_export.export import post_scan_exports
        aws_result = post_scan_exports(path, findings, scan_id=result.get("scan_id"), db=db)
        _print_aws_export_summary(aws_result)
    except Exception:
        pass

    console.print(f"\n[dim]Results saved to database. Run 'python main.py dashboard' to view.[/dim]")


def cmd_history_scan(path: str):
    """Scan Git commit history for leaked secrets."""
    from database import Database
    from git_history import scan_history

    path = os.path.abspath(path)
    if not os.path.isdir(os.path.join(path, ".git")):
        console.print(f"[red]Error:[/red] '{path}' is not a Git repository.")
        sys.exit(1)

    console.print(Panel(BANNER, style="bold cyan", border_style="cyan"))
    db = Database()
    from utils.logger import set_db
    set_db(db)

    console.print(f"\n[bold cyan]History scan:[/bold cyan] {path}\n")

    result = scan_history(path, db)
    if "error" in result:
        console.print(f"[red]Error:[/red] {result['error']}")
        sys.exit(1)

    results = result["findings"]
    db.add_log("INFO", "history", f"History scan complete: {len(results)} leaks in {path}")

    _print_history_table(results)

    console.print(f"\n[dim]Results saved. Run 'python main.py dashboard' to view.[/dim]")


def cmd_scan_remote(repo_url: str, run_history: bool = False):
    """Clone and scan a remote repository with mandatory allowlist enforcement."""
    from database import Database
    from rotation import bulk_rotate_critical
    from scanner.repo_ingestion import Allowlist, run_ingestion_scan
    from utils.logger import set_db

    console.print(Panel(BANNER, style="bold cyan", border_style="cyan"))
    db = Database()
    set_db(db)

    console.print(f"\n[bold cyan]Remote scan:[/bold cyan] {repo_url}\n")
    allowlist = Allowlist.load_default()
    result = run_ingestion_scan(
        repo_url,
        db,
        allowlist=allowlist,
        enforce_allowlist=True,
        run_history=run_history,
    )

    meta = result["metadata"]
    if not result.get("success"):
        console.print(f"[red]Scan failed:[/red] {result.get('error', meta.error)}")
        if meta.allowlist_reason:
            console.print(f"[dim]Allowlist: {meta.allowlist_reason}[/dim]")
        sys.exit(1)

    console.print(f"[green]✓ Allowlist:[/green] {meta.allowlist_reason}")
    console.print(f"[green]✓ Clone:[/green] {meta.clone_status} | [green]Cleanup:[/green] {meta.cleanup_status}")

    file_scan = result.get("file_scan") or {}
    findings = file_scan.get("findings", [])
    _print_findings_table(findings, title="Remote Scan Results")

    crit = [f for f in findings if f["severity"] == "Critical"]
    if crit:
        console.print(f"\n[bold red]⚠ {len(crit)} CRITICAL secrets found — triggering mock rotation...[/bold red]")
        rotations = bulk_rotate_critical(db)
        console.print(f"[green]✓ {len(rotations)} credentials rotated (mock)[/green]")

    if run_history:
        history_scan = result.get("history_scan") or {}
        if "error" in history_scan:
            console.print(f"[yellow]History scan warning:[/yellow] {history_scan['error']}")
        else:
            console.print("\n[bold magenta]History scan results:[/bold magenta]")
            _print_history_table(history_scan.get("findings", []))

    if result.get("aws_export"):
        _print_aws_export_summary(result["aws_export"])

    console.print(f"\n[dim]Results saved to database. Temporary clone cleaned up.[/dim]")


def cmd_scan_targets(targets_path: str, run_history: bool = False):
    """Batch scan targets defined in a YAML file."""
    from database import Database
    from scanner.repo_ingestion import scan_targets_batch
    from utils.logger import set_db

    targets_path = os.path.abspath(targets_path)
    if not os.path.isfile(targets_path):
        console.print(f"[red]Error:[/red] Targets file not found: {targets_path}")
        sys.exit(1)

    console.print(Panel(BANNER, style="bold cyan", border_style="cyan"))
    db = Database()
    set_db(db)

    console.print(f"\n[bold cyan]Batch scan:[/bold cyan] {targets_path}\n")
    batch = scan_targets_batch(targets_path, db, run_history=run_history)

    summary = batch["summary"]
    table = Table(title="Batch Scan Summary", box=box.ROUNDED, border_style="cyan")
    table.add_column("Target")
    table.add_column("Status", style="bold")
    table.add_column("File Findings", justify="right")
    table.add_column("History Findings", justify="right")
    table.add_column("Detail")

    for item in batch["results"]:
        target = item.get("target", "?")
        if item.get("skipped"):
            status = "[yellow]skipped[/yellow]"
            detail = item.get("error", "allowlist rejected")
            file_count = "—"
            hist_count = "—"
        elif item.get("success"):
            status = "[green]ok[/green]"
            meta = item["metadata"]
            file_count = str(meta.file_findings)
            hist_count = str(meta.history_findings)
            detail = meta.allowlist_reason or "completed"
        else:
            status = "[red]failed[/red]"
            meta = item.get("metadata")
            file_count = str(meta.file_findings) if meta else "—"
            hist_count = str(meta.history_findings) if meta else "—"
            detail = item.get("error", "unknown error")

        table.add_row(target, status, file_count, hist_count, detail[:60])

    console.print(table)
    console.print(
        f"\n[bold]Totals:[/bold] {summary['total']} targets | "
        f"[green]{summary['succeeded']} succeeded[/green] | "
        f"[red]{summary['failed']} failed[/red] | "
        f"[yellow]{summary['skipped']} skipped[/yellow] | "
        f"{summary['file_findings']} file findings | "
        f"{summary['history_findings']} history findings"
    )
    console.print(f"\n[dim]Results saved to database. Run 'python main.py dashboard' to view.[/dim]")

    if summary["failed"] > 0:
        sys.exit(1)


def cmd_monitor(path: str):
    """Monitor a repo for file changes in real-time."""
    from database import Database
    from monitor import WatchdogMonitor, PollingMonitor

    path = os.path.abspath(path)
    if not os.path.isdir(path):
        console.print(f"[red]Error:[/red] '{path}' is not a directory.")
        sys.exit(1)

    console.print(Panel(BANNER, style="bold cyan", border_style="cyan"))
    db = Database()
    repo_id = db.add_repo(path, os.path.basename(path))

    console.print(f"\n[bold cyan]Monitoring:[/bold cyan] {path}")
    console.print("[dim]Press Ctrl+C to stop.[/dim]\n")

    try:
        mon = WatchdogMonitor(path, db, repo_id)
        mon.start()
        console.print("[green]✓ Watchdog monitor active[/green]")
        while True:
            time.sleep(1)
    except Exception as e:
        console.print(f"[yellow]Watchdog failed ({e}), using polling fallback...[/yellow]")
        mon = PollingMonitor(path, db, repo_id)
        mon.start()
        console.print("[green]✓ Polling monitor active[/green]")
        while True:
            time.sleep(1)


def cmd_report():
    """Generate an HTML executive report."""
    from database import Database
    from reports import generate_report
    from utils.logger import set_db

    console.print(Panel(BANNER, style="bold cyan", border_style="cyan"))
    db = Database()
    set_db(db)

    console.print("\n[bold cyan]Generating report...[/bold cyan]")
    filepath, export_result = generate_report(db)
    console.print(f"[green]✓ Report saved:[/green] {filepath}")
    _print_s3_export_status(export_result)
    console.print(f"[dim]Open in your browser to view.[/dim]")


def cmd_aws_check():
    """Test AWS or LocalStack connectivity."""
    from cloud_export.aws_client import get_aws_client, reset_aws_client
    from cloud_export.localstack_health import localstack_guidance
    from config import get_aws_config

    reset_aws_client()
    console.print(Panel(BANNER, style="bold cyan", border_style="cyan"))
    cfg = get_aws_config()
    client = get_aws_client()

    console.print("\n[bold cyan]AWS Configuration[/bold cyan]")
    table = Table(box=box.SIMPLE, show_header=False)
    table.add_column("Key", style="dim")
    table.add_column("Value")
    for key, val in cfg.items():
        table.add_row(key, str(val) if val is not None else "(empty)")
    console.print(table)

    if not cfg.get("enabled"):
        console.print("\n[yellow][INFO][/yellow] AWS is [bold]disabled[/bold].")
        console.print("[dim]Set GITGUARD_AWS_ENABLED=true in .env or your shell to enable cloud export.[/dim]")
        return

    console.print("\n[green][INFO][/green] AWS is [bold]enabled[/bold].")

    if cfg.get("endpoint_url"):
        console.print(f"[green][INFO][/green] Using LocalStack endpoint: [cyan]{cfg['endpoint_url']}[/cyan]")
    else:
        console.print("[green][INFO][/green] Using real AWS (no custom endpoint).")

    result = client.validate_aws_connectivity()
    status = result.get("status", "unknown")

    if result.get("ok"):
        console.print(f"\n[green]✓ {result['detail']}[/green]")
        if status == "localstack_ready":
            console.print("[dim]LocalStack is reachable. S3 / SNS / DynamoDB exports can be attempted.[/dim]")
        elif status == "aws_connected":
            console.print(f"[dim]STS identity: {result.get('arn', 'n/a')}[/dim]")
        return

    if status == "localstack_unreachable":
        kind = result.get("error_kind")
        console.print(f"\n[yellow][WARNING][/yellow] {result.get('detail', 'Could not connect to LocalStack.')}")
        if result.get("hint") and kind in (None, "startup", "timeout", "unreachable"):
            console.print(f"[dim]{result['hint']}[/dim]")
        if kind in (None, "startup", "timeout", "unreachable"):
            console.print(f"\n[bold]Quick fix:[/bold]")
            for line in localstack_guidance(cfg.get("endpoint_url"), kind).split("\n"):
                console.print(f"  {line}")
        elif result.get("guidance"):
            for line in result["guidance"].split("\n"):
                console.print(f"  {line}")
        return

    if status == "validation_disabled":
        console.print(f"\n[yellow][INFO][/yellow] {result['detail']}")
        console.print("[dim]Cloud export may still work if credentials are configured in your environment.[/dim]")
        return

    if status in ("credentials_or_network", "connection_failed"):
        console.print(f"\n[yellow][WARNING][/yellow] {result.get('detail', 'Could not reach AWS')}")
        console.print("[dim]Check AWS credentials (aws configure) and network access.[/dim]")
        return

    console.print(f"\n[yellow][INFO][/yellow] {result.get('detail', 'Connectivity check incomplete')}")


def cmd_dashboard():
    """Launch the Flask dashboard."""
    console.print(Panel(BANNER, style="bold cyan", border_style="cyan"))
    from dashboard import run_dashboard
    run_dashboard()


def cmd_generate_test_repo():
    """Generate a demo test repository with fake secrets."""
    from test_repo_gen import generate_test_repo

    console.print(Panel(BANNER, style="bold cyan", border_style="cyan"))
    console.print("\n[bold cyan]Generating test repository...[/bold cyan]")
    repo_path = generate_test_repo()
    console.print(f"[green]✓ Test repo created:[/green] {repo_path}")
    console.print(f"[dim]Now run: python main.py scan {repo_path}[/dim]")


def main():
    if len(sys.argv) < 2:
        show_help()
        sys.exit(0)

    command = sys.argv[1].lower()

    if command == "scan" and len(sys.argv) >= 3:
        cmd_scan(sys.argv[2])
    elif command == "scan-remote" and len(sys.argv) >= 3:
        run_history = "--history" in sys.argv[3:]
        cmd_scan_remote(sys.argv[2], run_history=run_history)
    elif command == "scan-targets" and len(sys.argv) >= 3:
        run_history = "--history" in sys.argv[3:]
        cmd_scan_targets(sys.argv[2], run_history=run_history)
    elif command == "history-scan" and len(sys.argv) >= 3:
        cmd_history_scan(sys.argv[2])
    elif command == "monitor" and len(sys.argv) >= 3:
        cmd_monitor(sys.argv[2])
    elif command == "report":
        cmd_report()
    elif command == "aws-check":
        cmd_aws_check()
    elif command == "dashboard":
        cmd_dashboard()
    elif command == "generate-test-repo":
        cmd_generate_test_repo()
    elif command in ("help", "--help", "-h"):
        show_help()
    else:
        console.print(f"[red]Unknown command:[/red] {command}")
        show_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
