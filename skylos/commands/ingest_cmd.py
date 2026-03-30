import argparse
import json


def run_ingest_command(
    argv: list[str],
    *,
    console_factory,
) -> int:
    ingest_parser = argparse.ArgumentParser(
        prog="skylos ingest", description="Ingest findings from external tools"
    )
    ingest_sub = ingest_parser.add_subparsers(dest="ingest_cmd")

    p_ccs = ingest_sub.add_parser(
        "claude-security", help="Ingest Claude Code Security JSON"
    )
    p_ccs.add_argument(
        "--input",
        "-i",
        required=True,
        dest="input_file",
        help="Path to Claude Code Security JSON output",
    )
    p_ccs.add_argument(
        "--token",
        default=None,
        help="API token (falls back to SKYLOS_TOKEN / keyring)",
    )
    p_ccs.add_argument(
        "--no-upload",
        action="store_true",
        help="Normalize only, don't upload to dashboard",
    )
    p_ccs.add_argument(
        "--json",
        action="store_true",
        dest="output_json",
        help="Output normalized result as JSON",
    )
    p_ccs.add_argument(
        "--cross-reference",
        dest="cross_ref",
        help="Skylos results JSON to cross-reference (shows attack surface reduction)",
    )

    if not argv:
        ingest_parser.print_help()
        return 0

    ingest_args = ingest_parser.parse_args(argv)

    if ingest_args.ingest_cmd == "claude-security":
        from skylos.ingest import ingest_claude_security

        result = ingest_claude_security(
            ingest_args.input_file,
            upload=not ingest_args.no_upload,
            token=ingest_args.token,
            cross_reference_path=ingest_args.cross_ref,
        )

        if ingest_args.output_json:
            normalized = result.get("result")
            if normalized:
                print(json.dumps(normalized, indent=2))
            elif result.get("upload"):
                print(json.dumps(result["upload"], indent=2))

        if not result.get("success"):
            console_factory().print(
                f"[bold red]Ingest failed: {result.get('error', 'unknown')}[/bold red]"
            )
            return 1

        console_factory().print(
            f"[green]Ingested {result.get('findings_count', 0)} findings[/green]"
        )
    else:
        ingest_parser.print_help()

    return 0
