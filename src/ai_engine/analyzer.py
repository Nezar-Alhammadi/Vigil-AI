"""
Vigil-AI — AI Analysis Engine
==============================
Sends High/Medium Slither findings to an LLM via OpenRouter and assembles
a structured Markdown audit report.

Environment
-----------
    OPENROUTER_API_KEY  (required)  Your OpenRouter API key.

Usage
-----
    from ai_engine.analyzer import AIEngine

    engine = AIEngine()
    report_md = engine.analyze_vulnerabilities(detectors, project_root)
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from openai import OpenAI
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

console = Console()

# ── Constants ────────────────────────────────────────────────────────────────

_DEFAULT_MODEL  = "anthropic/claude-3.5-sonnet"
_OPENROUTER_URL = "https://openrouter.ai/api/v1"
_IMPACT_FILTER  = {"High", "Medium"}
_CONTEXT_LINES  = 5

_SYSTEM_PROMPT = (
    "You are a senior Web3 security auditor specialising in Solidity, Vyper, "
    "DeFi protocols, and EVM internals. "
    "You produce professional, actionable security audit reports in Markdown. "
    "You MUST respond ONLY with the exact Markdown template you are given — "
    "no preamble, no commentary, no extra text outside the template."
)


# ── Main class ───────────────────────────────────────────────────────────────

class AIEngine:
    """
    Orchestrates per-finding LLM calls and assembles the final audit report.

    Parameters
    ----------
    model   : OpenRouter model identifier (default: anthropic/claude-3.5-sonnet).
    api_key : Override for OPENROUTER_API_KEY env-var (useful for testing).
    """

    def __init__(
        self,
        model: str = _DEFAULT_MODEL,
        api_key: Optional[str] = None,
    ) -> None:
        resolved_key = api_key or os.environ.get("OPENROUTER_API_KEY", "")
        if not resolved_key:
            raise EnvironmentError(
                "OPENROUTER_API_KEY environment variable is not set.\n"
                "Export it with:  export OPENROUTER_API_KEY=<your_key>"
            )

        self._model  = model
        self._client = OpenAI(api_key=resolved_key, base_url=_OPENROUTER_URL)

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze_vulnerabilities(self, detectors: list, project_root: str) -> str:
        """
        Filter ``detectors`` to High/Medium findings, call the LLM for each,
        and return one consolidated Markdown report string.

        Parameters
        ----------
        detectors    : Raw list of detector dicts from Slither's JSON output.
        project_root : Absolute path to the scanned project root.

        Returns
        -------
        A Markdown string ready to be written to ``Audit_Report.md``.
        """
        targets = [d for d in detectors if d.get("impact") in _IMPACT_FILTER]

        if not targets:
            return (
                "## No High or Medium severity vulnerabilities found to analyze.\n\n"
                "Only lower-severity findings were detected by Slither. "
                "Re-run with a broader filter if needed."
            )

        header   = _build_report_header(project_root, len(targets), self._model)
        sections: list[str] = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            transient=False,
        ) as progress:
            task_id = progress.add_task(
                "[cyan]AI Analysis — starting...", total=len(targets)
            )

            for idx, detector in enumerate(targets, start=1):
                rule   = detector.get("check", "unknown-rule")
                impact = detector.get("impact", "Unknown")

                color = "bold red" if impact == "High" else "bold yellow"
                progress.update(
                    task_id,
                    description=(
                        f"[cyan]Analysing [bold white]{rule}[/bold white] "
                        f"([{color}]{impact}[/{color}]) "
                        f"[dim]({idx}/{len(targets)})[/dim]"
                    ),
                )

                code_snippet, file_path = self._extract_code_context(
                    detector, project_root
                )
                section_md = self._call_llm(
                    rule=rule,
                    impact=impact,
                    description=detector.get("description", "").strip(),
                    code_snippet=code_snippet,
                    file_path=file_path,
                )
                sections.append(section_md)
                progress.advance(task_id)

        progress.stop()
        console.print(
            f"[bold green]AI analysis complete.[/bold green] "
            f"{len(sections)} finding(s) processed."
        )

        return header + "\n\n---\n\n".join(sections)

    # ── Private helpers ───────────────────────────────────────────────────────

    def _extract_code_context(
        self, detector: dict, project_root: str
    ) -> tuple[str, str]:
        """
        Walk the detector's ``elements``, find the first resolvable source file,
        and return ``(code_snippet_with_context, resolved_file_path_str)``.

        Falls back to the raw Slither description if no file can be located or
        read (e.g. on-chain contracts written to a temp directory that has since
        been cleaned up, or missing absolute paths on a different machine).
        """
        root = Path(project_root)

        for element in detector.get("elements", []):
            sm = element.get("source_mapping", {})
            if not sm:
                continue

            file_path = _resolve_source_file(
                sm.get("filename_absolute", ""),
                sm.get("filename_relative", ""),
                root,
            )
            if file_path is None:
                continue

            lines: list[int] = sm.get("lines", [])
            snippet = _read_with_context(file_path, lines, _CONTEXT_LINES)
            if snippet:
                return snippet, str(file_path)

        # Fallback: use the plain Slither description as pseudo-code context.
        fallback = detector.get("description", "No source mapping available.")
        return fallback, project_root

    def _call_llm(
        self,
        rule: str,
        impact: str,
        description: str,
        code_snippet: str,
        file_path: str,
    ) -> str:
        """Send one finding to the LLM and return its Markdown response."""
        template     = _build_template(rule, impact, file_path)
        user_message = (
            f"**Slither Detector:** `{rule}`\n"
            f"**Impact:** {impact}\n"
            f"**Slither Description:**\n{description}\n\n"
            f"**Source Code (file: `{file_path}`):**\n"
            f"```solidity\n{code_snippet}\n```\n\n"
            "Complete the following audit-report template by replacing every "
            "`[bracketed]` placeholder with your analysis. "
            "Produce ONLY the completed template — no extra text before or after.\n\n"
            f"{template}"
        )

        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user",   "content": user_message},
                ],
                temperature=0.2,
                max_tokens=2048,
            )
            content = response.choices[0].message.content
            if not content or not content.strip():
                return _error_section(rule, impact, "Empty response received from LLM.")
            return content.strip()

        except Exception as exc:  # noqa: BLE001
            return _error_section(rule, impact, str(exc))


# ── Template builders ────────────────────────────────────────────────────────

def _build_template(rule: str, impact: str, file_path: str) -> str:
    """Return the structured audit-report template with known fields pre-filled."""
    return (
        f"## [{rule}: Write a concise, professional title]\n\n"
        f"**Impact:** {impact}\n"
        f"**Likelihood:** [Determine High/Medium/Low based on context]\n\n"
        f"**Scope:**\n"
        f"- `{file_path}`\n\n"
        "### Description\n"
        "**Root + Impact**\n"
        "[Describe the normal behavior and explain the specific issue in detail based on the code]\n\n"
        "```solidity\n"
        "// Root cause in the codebase with @> marks to highlight the relevant section\n"
        "[Snippet of the exact vulnerable code]\n"
        "```\n\n"
        "**Risk**\n\n"
        "Likelihood:\n\n"
        "- [Reason 1: Describe WHEN this will occur]\n\n"
        "- [Reason 2]\n\n"
        "Impact:\n\n"
        "- [Impact 1]\n\n"
        "### Proof of Concept\n"
        "```solidity\n"
        "[Write a conceptual Foundry test or detailed explanation demonstrating the exploit]\n"
        "```\n\n"
        "### Recommended Mitigation\n"
        "```diff\n"
        "- [Vulnerable code to remove]\n"
        "+ [Secure code to add]\n"
        "```\n"
    )


def _build_report_header(project_root: str, vuln_count: int, model: str) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return (
        "# Vigil-AI Security Audit Report\n\n"
        "| | |\n"
        "|---|---|\n"
        f"| **Project** | `{project_root}` |\n"
        f"| **Generated** | {now} |\n"
        f"| **High/Medium Findings** | {vuln_count} |\n"
        f"| **Model** | `{model}` |\n\n"
        "---\n\n"
    )


def _error_section(rule: str, impact: str, error_msg: str) -> str:
    return (
        f"## [{rule}: Analysis Failed]\n\n"
        f"**Impact:** {impact}\n\n"
        f"> **Error:** Could not generate AI analysis.\n"
        f"> `{error_msg}`\n"
    )


# ── Source-file resolution ───────────────────────────────────────────────────

def _resolve_source_file(
    filename_absolute: str,
    filename_relative: str,
    project_root: Path,
) -> Optional[Path]:
    """
    Locate the contract source file using a three-stage strategy:

    1. Use ``filename_absolute`` directly (fast path, works on the same machine).
    2. Join ``project_root`` with the stripped ``filename_relative``.
    3. Recursive glob by filename stem inside ``project_root`` (last resort,
       handles cases where the repo was moved or the temp dir path differs).
    """
    # Stage 1 — absolute path
    if filename_absolute:
        p = Path(filename_absolute)
        if p.is_file():
            return p

    if filename_relative:
        # Stage 2 — relative path from project root
        rel = filename_relative.lstrip("/\\")
        p = project_root / rel
        if p.is_file():
            return p

        # Stage 3 — search by filename only
        name_only = Path(filename_relative).name
        if name_only:
            hits = list(project_root.rglob(name_only))
            if hits:
                return hits[0]

    return None


# ── Line-level code extraction ───────────────────────────────────────────────

def _read_with_context(
    file_path: Path,
    lines: list[int],
    context: int,
) -> str:
    """
    Read ``lines`` (1-indexed, as reported by Slither) from ``file_path``
    with ``context`` surrounding lines above and below.

    Vulnerable lines are marked with ``@>``; surrounding lines with two spaces.
    Returns an empty string on any read error so callers can fall back gracefully.
    """
    if not lines:
        return ""

    try:
        all_lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""

    total    = len(all_lines)
    first_0  = min(lines) - 1          # convert to 0-indexed
    last_0   = max(lines) - 1
    start    = max(0, first_0 - context)
    end      = min(total - 1, last_0 + context)
    line_set = set(lines)

    result: list[str] = []
    for i in range(start, end + 1):
        lineno = i + 1                  # back to 1-indexed for display
        marker = "@>" if lineno in line_set else "  "
        result.append(f"{marker} {lineno:>4} | {all_lines[i]}")

    return "\n".join(result)
