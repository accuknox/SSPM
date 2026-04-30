"""
AccuKnox SSPM CLI.

Usage examples:

    # Scan an MS365 tenant — produces report.html + report.sarif.json
    sspm scan ms365 \\
        --tenant-id  <GUID>        \\
        --client-id  <GUID>        \\
        --client-secret <secret>   \\
        --tenant-domain contoso.onmicrosoft.com

    # Custom output stem (generates contoso.html + contoso.sarif.json)
    sspm scan ms365 ... --output contoso

    # SARIF only (skip HTML)
    sspm scan ms365 ... --no-html

    # Scan with a profile filter
    sspm scan ms365 ... --profile "E3 Level 1"

    # List all registered rules
    sspm rules list

    # Render an HTML report from an existing SARIF file
    sspm report html report.sarif.json

    # Show SARIF summary from an existing report
    sspm report summary report.sarif.json
"""

from __future__ import annotations

import asyncio
import json
import sys

import click
from rich.console import Console
from rich.table import Table

console = Console()


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------


@click.group()
@click.version_option(package_name="accuknox-sspm")
def main() -> None:
    """AccuKnox SSPM – SaaS Security Posture Management scanner."""


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


@main.group()
def scan() -> None:
    """Run a security posture scan against a SaaS provider."""


@scan.command("gws")
@click.option(
    "--service-account-key", required=True, envvar="SSPM_GWS_SA_KEY",
    help="Path to Google service account JSON key file.",
)
@click.option(
    "--admin-email", required=True, envvar="SSPM_GWS_ADMIN_EMAIL",
    help="Super admin email address to impersonate via domain-wide delegation.",
)
@click.option(
    "--customer-domain", default="", envvar="SSPM_GWS_CUSTOMER_DOMAIN",
    help="Primary domain of the Google Workspace organisation (e.g. example.com).",
)
@click.option("--profile", default=None, help='CIS profile filter: "Enterprise Level 1", "Enterprise Level 2".')
@click.option("--rule", "rule_ids", multiple=True, help="Limit scan to specific rule IDs (repeatable).")
@click.option(
    "--output", "-o", default="sspm-gws-report", show_default=True,
    help="Output file stem. Produces <stem>.html and <stem>.sarif.json.",
)
@click.option("--no-html", is_flag=True, default=False, help="Skip HTML report generation.")
@click.option("--no-sarif", is_flag=True, default=False, help="Skip SARIF report generation.")
@click.option("--verbose", "-v", is_flag=True, help="Show individual findings in the terminal.")
def scan_gws(
    service_account_key: str,
    admin_email: str,
    customer_domain: str,
    profile: str | None,
    rule_ids: tuple[str, ...],
    output: str,
    no_html: bool,
    no_sarif: bool,
    verbose: bool,
) -> None:
    """Scan a Google Workspace tenant against CIS GWS Foundations Benchmark v1.3.0."""
    import logging

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    from sspm.core.engine import ScanEngine
    from sspm.core.html_reporter import write_html
    from sspm.core.reporter import write_sarif
    from sspm.providers.gws.provider import GWSProvider

    provider = GWSProvider(
        service_account_key=service_account_key,
        admin_email=admin_email,
        customer_domain=customer_domain or admin_email.split("@")[-1],
    )

    engine = ScanEngine(
        provider=provider,
        profile_filter=profile,
        rule_ids=list(rule_ids) if rule_ids else None,
    )

    console.print(f"[bold]AccuKnox SSPM[/bold] – scanning [cyan]{provider.target}[/cyan] (Google Workspace)")
    if profile:
        console.print(f"  Profile filter: [yellow]{profile}[/yellow]")

    result = asyncio.run(engine.scan())

    stem = output
    for ext in (".html", ".sarif.json", ".sarif", ".json"):
        if stem.endswith(ext):
            stem = stem[: -len(ext)]
            break

    console.print()
    if not no_html:
        html_path = f"{stem}.html"
        write_html(result, html_path)
        console.print(f"[green]HTML  report:[/green] {html_path}")

    if not no_sarif:
        sarif_path = f"{stem}.sarif.json"
        write_sarif(result, sarif_path)
        console.print(f"[green]SARIF report:[/green] {sarif_path}")

    _print_summary(result, verbose=verbose)

    if result.failed:
        sys.exit(1)


@scan.command("aws")
@click.option("--access-key-id", default=None, envvar="AWS_ACCESS_KEY_ID",
              help="AWS access key ID. If omitted, uses the standard credential chain.")
@click.option("--secret-access-key", default=None, envvar="AWS_SECRET_ACCESS_KEY",
              help="AWS secret access key.")
@click.option("--session-token", default=None, envvar="AWS_SESSION_TOKEN",
              help="AWS STS session token (for temporary credentials).")
@click.option("--profile", "aws_profile", default=None, envvar="AWS_PROFILE",
              help="Named AWS CLI profile (~/.aws/credentials).")
@click.option("--region", default="us-east-1", show_default=True, envvar="AWS_DEFAULT_REGION",
              help="Home region for global API calls.")
@click.option("--account-alias", default="", envvar="SSPM_AWS_ACCOUNT_ALIAS",
              help="Human-readable label for the account (defaults to account ID).")
@click.option("--profile-filter", "profile_filter", default=None,
              help='CIS profile filter: "AWS Level 1" or "AWS Level 2".')
@click.option("--rule", "rule_ids", multiple=True, help="Limit scan to specific rule IDs (repeatable).")
@click.option("--output", "-o", default="sspm-aws-report", show_default=True,
              help="Output file stem. Produces <stem>.html and <stem>.sarif.json.")
@click.option("--no-html", is_flag=True, default=False, help="Skip HTML report generation.")
@click.option("--no-sarif", is_flag=True, default=False, help="Skip SARIF report generation.")
@click.option("--verbose", "-v", is_flag=True, help="Show individual findings in the terminal.")
def scan_aws(
    access_key_id: str | None,
    secret_access_key: str | None,
    session_token: str | None,
    aws_profile: str | None,
    region: str,
    account_alias: str,
    profile_filter: str | None,
    rule_ids: tuple[str, ...],
    output: str,
    no_html: bool,
    no_sarif: bool,
    verbose: bool,
) -> None:
    """Scan an AWS account against CIS AWS Foundations Benchmark v1.2.0."""
    import logging

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    from sspm.core.engine import ScanEngine
    from sspm.core.html_reporter import write_html
    from sspm.core.reporter import write_sarif
    from sspm.providers.aws.provider import AWSProvider

    provider = AWSProvider(
        access_key_id=access_key_id or None,
        secret_access_key=secret_access_key or None,
        session_token=session_token or None,
        profile_name=aws_profile or None,
        region_name=region,
        account_alias=account_alias,
    )

    engine = ScanEngine(
        provider=provider,
        profile_filter=profile_filter,
        rule_ids=list(rule_ids) if rule_ids else None,
    )

    console.print(f"[bold]AccuKnox SSPM[/bold] – scanning [cyan]{provider.target}[/cyan] (AWS)")
    if profile_filter:
        console.print(f"  Profile filter: [yellow]{profile_filter}[/yellow]")

    result = asyncio.run(engine.scan())

    stem = output
    for ext in (".html", ".sarif.json", ".sarif", ".json"):
        if stem.endswith(ext):
            stem = stem[: -len(ext)]
            break

    console.print()
    if not no_html:
        html_path = f"{stem}.html"
        write_html(result, html_path)
        console.print(f"[green]HTML  report:[/green] {html_path}")

    if not no_sarif:
        sarif_path = f"{stem}.sarif.json"
        write_sarif(result, sarif_path)
        console.print(f"[green]SARIF report:[/green] {sarif_path}")

    _print_summary(result, verbose=verbose)

    if result.failed:
        sys.exit(1)


@scan.command("azure")
@click.option("--tenant-id", required=True, envvar="AZURE_TENANT_ID", help="Entra tenant ID (GUID).")
@click.option("--client-id", required=True, envvar="AZURE_CLIENT_ID", help="App registration client ID.")
@click.option("--client-secret", required=True, envvar="AZURE_CLIENT_SECRET", help="App registration client secret.")
@click.option("--subscription-id", required=True, envvar="AZURE_SUBSCRIPTION_ID",
              help="Azure subscription ID to scan.")
@click.option("--subscription-label", default="", envvar="SSPM_AZURE_SUBSCRIPTION_LABEL",
              help="Human-readable label for the subscription (defaults to the subscription ID).")
@click.option("--profile", "profile_filter", default=None,
              help='CIS profile filter: "Azure Level 1" or "Azure Level 2".')
@click.option("--rule", "rule_ids", multiple=True, help="Limit scan to specific rule IDs (repeatable).")
@click.option("--output", "-o", default="sspm-azure-report", show_default=True,
              help="Output file stem. Produces <stem>.html and <stem>.sarif.json.")
@click.option("--no-html", is_flag=True, default=False, help="Skip HTML report generation.")
@click.option("--no-sarif", is_flag=True, default=False, help="Skip SARIF report generation.")
@click.option("--verbose", "-v", is_flag=True, help="Show individual findings in the terminal.")
def scan_azure(
    tenant_id: str,
    client_id: str,
    client_secret: str,
    subscription_id: str,
    subscription_label: str,
    profile_filter: str | None,
    rule_ids: tuple[str, ...],
    output: str,
    no_html: bool,
    no_sarif: bool,
    verbose: bool,
) -> None:
    """Scan an Azure subscription against CIS Microsoft Azure Foundations Benchmark v6.0.0."""
    import logging

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    from sspm.core.engine import ScanEngine
    from sspm.core.html_reporter import write_html
    from sspm.core.reporter import write_sarif
    from sspm.providers.azure.provider import AzureProvider

    provider = AzureProvider(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        subscription_id=subscription_id,
        subscription_label=subscription_label,
    )

    engine = ScanEngine(
        provider=provider,
        profile_filter=profile_filter,
        rule_ids=list(rule_ids) if rule_ids else None,
    )

    console.print(f"[bold]AccuKnox SSPM[/bold] – scanning [cyan]{provider.target}[/cyan] (Azure)")
    if profile_filter:
        console.print(f"  Profile filter: [yellow]{profile_filter}[/yellow]")

    result = asyncio.run(engine.scan())

    stem = output
    for ext in (".html", ".sarif.json", ".sarif", ".json"):
        if stem.endswith(ext):
            stem = stem[: -len(ext)]
            break

    console.print()
    if not no_html:
        html_path = f"{stem}.html"
        write_html(result, html_path)
        console.print(f"[green]HTML  report:[/green] {html_path}")

    if not no_sarif:
        sarif_path = f"{stem}.sarif.json"
        write_sarif(result, sarif_path)
        console.print(f"[green]SARIF report:[/green] {sarif_path}")

    _print_summary(result, verbose=verbose)

    if result.failed:
        sys.exit(1)


@scan.command("ms365")
@click.option("--tenant-id", required=True, envvar="SSPM_TENANT_ID", help="Entra tenant ID (GUID).")
@click.option("--client-id", required=True, envvar="SSPM_CLIENT_ID", help="App registration client ID.")
@click.option("--client-secret", required=True, envvar="SSPM_CLIENT_SECRET", help="App registration client secret.")
@click.option("--tenant-domain", default="", envvar="SSPM_TENANT_DOMAIN", help="Tenant domain label (e.g. contoso.onmicrosoft.com).")
@click.option("--profile", default=None, help='CIS profile filter: "E3 Level 1", "E3 Level 2", "E5 Level 1", "E5 Level 2".')
@click.option("--rule", "rule_ids", multiple=True, help="Limit scan to specific rule IDs (repeatable).")
@click.option(
    "--output", "-o", default="sspm-report", show_default=True,
    help="Output file stem. Produces <stem>.html and <stem>.sarif.json by default.",
)
@click.option("--no-html", is_flag=True, default=False, help="Skip HTML report generation.")
@click.option("--no-sarif", is_flag=True, default=False, help="Skip SARIF report generation.")
@click.option("--verbose", "-v", is_flag=True, help="Show individual findings in the terminal.")
def scan_ms365(
    tenant_id: str,
    client_id: str,
    client_secret: str,
    tenant_domain: str,
    profile: str | None,
    rule_ids: tuple[str, ...],
    output: str,
    no_html: bool,
    no_sarif: bool,
    verbose: bool,
) -> None:
    """Scan a Microsoft 365 tenant against CIS Foundations Benchmark v6.0.1."""
    import logging

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    from sspm.core.engine import ScanEngine
    from sspm.core.html_reporter import write_html
    from sspm.core.reporter import write_sarif
    from sspm.providers.ms365.provider import MS365Provider

    provider = MS365Provider(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        tenant_domain=tenant_domain or tenant_id,
    )

    engine = ScanEngine(
        provider=provider,
        profile_filter=profile,
        rule_ids=list(rule_ids) if rule_ids else None,
    )

    console.print(f"[bold]AccuKnox SSPM[/bold] – scanning [cyan]{provider.target}[/cyan]")
    if profile:
        console.print(f"  Profile filter: [yellow]{profile}[/yellow]")

    result = asyncio.run(engine.scan())

    # Strip any extension the user may have supplied so we control both outputs
    stem = output
    for ext in (".html", ".sarif.json", ".sarif", ".json"):
        if stem.endswith(ext):
            stem = stem[: -len(ext)]
            break

    console.print()
    if not no_html:
        html_path = f"{stem}.html"
        write_html(result, html_path)
        console.print(f"[green]HTML  report:[/green] {html_path}")

    if not no_sarif:
        sarif_path = f"{stem}.sarif.json"
        write_sarif(result, sarif_path)
        console.print(f"[green]SARIF report:[/green] {sarif_path}")

    _print_summary(result, verbose=verbose)

    # Exit 1 if there are failures
    if result.failed:
        sys.exit(1)


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------


@main.group()
def rules() -> None:
    """Inspect registered rules."""


@rules.command("list")
@click.option("--provider", default=None, help="Filter by provider ID (e.g. ms365).")
@click.option("--profile", default=None, help="Filter by CIS profile.")
def rules_list(provider: str | None, profile: str | None) -> None:
    """List all registered security rules."""
    # Trigger auto-discovery for known providers
    if not provider or provider == "ms365":
        from sspm.providers.ms365.provider import MS365Provider  # noqa: F401
        MS365Provider._autodiscover()
    if not provider or provider == "gws":
        from sspm.providers.gws.provider import GWSProvider  # noqa: F401
        GWSProvider._autodiscover()
    if not provider or provider == "aws":
        from sspm.providers.aws.provider import AWSProvider  # noqa: F401
        AWSProvider._autodiscover()
    if not provider or provider == "azure":
        from sspm.providers.azure.provider import AzureProvider  # noqa: F401
        AzureProvider._autodiscover()

    from sspm.core.models import CISProfile
    from sspm.core.registry import registry

    if profile:
        rule_list = registry.rules_for_profile(profile)
    elif provider:
        rule_list = registry.rules_for_provider(provider)
    else:
        rule_list = registry.all_rules()

    table = Table(title=f"Registered Rules ({len(rule_list)} total)", show_lines=False)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Title", max_width=50)
    table.add_column("Status", justify="center")
    table.add_column("Severity", justify="center")
    table.add_column("Profiles")

    status_styles = {"automated": "green", "manual": "yellow"}
    sev_styles = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    for rule in sorted(rule_list, key=lambda r: r.metadata.id):
        m = rule.metadata
        status_style = status_styles.get(m.assessment_status.value, "")
        sev_style = sev_styles.get(m.severity.value, "")
        profiles = ", ".join(p.value for p in m.profiles)
        table.add_row(
            m.id,
            m.title,
            f"[{status_style}]{m.assessment_status.value}[/{status_style}]",
            f"[{sev_style}]{m.severity.value}[/{sev_style}]",
            profiles,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


@main.group()
def report() -> None:
    """Inspect SARIF report files."""


@report.command("html")
@click.argument("sarif_file", type=click.Path(exists=True))
@click.option("--output", "-o", default=None, help="Output HTML path (defaults to <sarif_file>.html).")
def report_html(sarif_file: str, output: str | None) -> None:
    """Render an HTML report from an existing SARIF file."""
    import json as _json

    from sspm.core.html_reporter import write_html
    from sspm.core.models import (
        AssessmentStatus,
        CISProfile,
        Evidence,
        Finding,
        FindingStatus,
        RuleMetadata,
        ScanResult,
        Severity,
    )

    with open(sarif_file, encoding="utf-8") as fh:
        doc = _json.load(fh)

    run = doc["runs"][0]
    invocation = (run.get("invocations") or [{}])[0]
    props = invocation.get("properties", {})
    run_props = run.get("properties", {})

    # Reconstruct a minimal ScanResult from the SARIF document
    result = ScanResult(
        scan_id=props.get("scanId", ""),
        target=props.get("target", run.get("tool", {}).get("driver", {}).get("properties", {}).get("provider", "")),
        provider=run.get("tool", {}).get("driver", {}).get("properties", {}).get("provider", ""),
        benchmark=run.get("tool", {}).get("driver", {}).get("properties", {}).get("benchmark", ""),
        started_at=invocation.get("startTimeUtc", ""),
        completed_at=invocation.get("endTimeUtc", ""),
    )

    # Build a rule metadata map from the driver rules
    rule_map: dict[str, RuleMetadata] = {}
    for rd in run.get("tool", {}).get("driver", {}).get("rules", []):
        rp = rd.get("properties", {})
        try:
            profiles = [CISProfile(p) for p in rp.get("profiles", [])]
        except ValueError:
            profiles = []
        try:
            sev = Severity(rp.get("severity", "medium"))
        except ValueError:
            sev = Severity.MEDIUM
        try:
            assess = AssessmentStatus(rp.get("assessmentStatus", "automated"))
        except ValueError:
            assess = AssessmentStatus.AUTOMATED

        rule_map[rd["id"]] = RuleMetadata(
            id=rd["id"],
            title=rd.get("name", rd["id"]),
            section=rp.get("section", ""),
            benchmark=rp.get("benchmark", ""),
            assessment_status=assess,
            profiles=profiles,
            severity=sev,
            description=rd.get("fullDescription", {}).get("text", ""),
            rationale="",
            impact="",
            audit_procedure="",
            remediation="",
            default_value=rp.get("defaultValue", ""),
            references=[rd.get("helpUri", "")] if rd.get("helpUri") else [],
        )

    for res in run.get("results", []):
        rule_id = res.get("ruleId", "")
        rule_meta = rule_map.get(rule_id)
        if rule_meta is None:
            continue
        rp = res.get("properties", {})
        raw_status = rp.get("status", res.get("kind", "pass"))
        try:
            status = FindingStatus(raw_status)
        except ValueError:
            status = FindingStatus.PASS

        evidence = []
        for rl in res.get("relatedLocations", []):
            ev_data = rl.get("properties", {}).get("data")
            ev_msg = rl.get("message", {}).get("text", "")
            src = ev_msg.split(":")[0] if ":" in ev_msg else ev_msg
            desc = ev_msg[len(src) + 2:] if ":" in ev_msg else ""
            evidence.append(Evidence(source=src, data=ev_data, description=desc))

        result.findings.append(
            Finding(
                rule=rule_meta,
                status=status,
                resource_id=rp.get("resourceId", ""),
                resource_type=rp.get("resourceType", ""),
                message=res.get("message", {}).get("text", ""),
                evidence=evidence,
            )
        )

    out_path = output or sarif_file.replace(".sarif.json", "").replace(".sarif", "").replace(".json", "") + ".html"
    write_html(result, out_path)
    console.print(f"[green]HTML report written to:[/green] {out_path}")


@report.command("summary")
@click.argument("sarif_file", type=click.Path(exists=True))
def report_summary(sarif_file: str) -> None:
    """Print a summary of a SARIF report file."""
    with open(sarif_file, encoding="utf-8") as fh:
        doc = json.load(fh)

    run = doc["runs"][0]
    results = run.get("results", [])

    counts: dict[str, int] = {}
    for r in results:
        status = r.get("properties", {}).get("status", r.get("kind", "unknown"))
        counts[status] = counts.get(status, 0) + 1

    props = run.get("properties", {}).get("summary", counts)

    table = Table(title=f"Report Summary: {sarif_file}", show_header=False)
    table.add_column("Metric", style="bold")
    table.add_column("Count", justify="right")

    styles = {"passed": "green", "failed": "red", "manual": "yellow", "errors": "magenta", "skipped": "dim"}
    for key, val in props.items():
        style = styles.get(key, "")
        table.add_row(f"[{style}]{key.capitalize()}[/{style}]", str(val))

    console.print(table)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _print_summary(result, verbose: bool = False) -> None:
    from sspm.core.models import FindingStatus

    summary = result.summary()

    table = Table(title="Scan Summary", show_header=False)
    table.add_column("Metric", style="bold")
    table.add_column("Count", justify="right")

    table.add_row("[green]Passed[/green]", str(summary["passed"]))
    table.add_row("[red]Failed[/red]", str(summary["failed"]))
    table.add_row("[yellow]Manual[/yellow]", str(summary["manual"]))
    table.add_row("[magenta]Errors[/magenta]", str(summary["errors"]))
    table.add_row("[dim]Skipped[/dim]", str(summary["skipped"]))
    table.add_row("Total", str(summary["total"]))

    console.print(table)

    if verbose:
        if result.failed:
            console.print("\n[bold red]Failed:[/bold red]")
            for f in result.failed:
                console.print(f"  [red]✗[/red] [{f.rule.severity.value}] {f.rule.id}: {f.message}")
        if result.manual:
            console.print("\n[bold yellow]Manual review required:[/bold yellow]")
            for f in result.manual:
                console.print(f"  [yellow]?[/yellow] {f.rule.id}: {f.rule.title}")
        if result.errors:
            console.print("\n[bold magenta]Errors:[/bold magenta]")
            for f in result.errors:
                console.print(f"  [magenta]![/magenta] {f.rule.id}: {f.message}")
