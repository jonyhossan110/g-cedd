"""Terminal UI banner with ANSI colors and personal branding."""

from __future__ import annotations

# ANSI color codes for Kali Linux terminal compatibility
C = "\033[96m"       # cyan
BC = "\033[1;96m"    # bold cyan
BG = "\033[1;92m"    # bold green
Y = "\033[93m"       # yellow
W = "\033[97m"       # white
BW = "\033[1;97m"    # bold white
R = "\033[0m"        # reset


def _row(left: str, content: str, right: str) -> str:
    """Build a single banner row."""
    return f"{left}{content}{right}"


def print_banner() -> None:
    """Print the G-CEDD ASCII banner with ANSI colors and credits."""
    # Top border
    top = f"{BC}{'╔' + '═' * 67 + '╗'}{R}"
    bot = f"{BC}{'╚' + '═' * 67 + '╝'}{R}"
    vl = f"{BC}║{R}"
    sp = " " * 67

    # Inner box logos
    logo1 = f"  {BG}╔═══════╗ ╔═══════╗{R}" + " " * 46
    logo2 = f"  {BG}║ G C - ║ ║ DEEP  ║{R}" + " " * 46
    logo3 = f"  {BG}╚═══════╝ ╚═══════╝{R}" + " " * 46
    title = f"        {BW}Git & Config Exposure Deep-Dive Auditor{R}" + " " * 20

    # Credits box
    ct = f"{Y}{'┌' + '─' * 65 + '┐'}{R}"
    cb = f"{Y}{'└' + '─' * 65 + '┘'}{R}"
    cv = f"{Y}│{R}"
    cr1 = (
        f"  {W}Created By:{R} "
        f"{BG}Md. Jony Hassain (HexaCyberLab){R}"
        + " " * 20
    )
    cr2 = (
        f"  {W}LinkedIn:{R}   "
        f"{C}https://www.linkedin.com/in/md-jony-hassain/{R}"
        + " " * 8
    )

    lines = [
        "",
        top,
        _row(vl, sp, vl),
        _row(vl, logo1, vl),
        _row(vl, logo2, vl),
        _row(vl, logo3, vl),
        _row(vl, sp, vl),
        _row(vl, title, vl),
        _row(vl, sp, vl),
        bot,
        "",
        ct,
        _row(cv, cr1, cv),
        _row(cv, cr2, cv),
        cb,
        "",
    ]
    print("\n".join(lines))

# Updated by Jony on 03/26/2026 02:35:36
