#!/usr/bin/env python3
"""
Unicode & encoding attack scanner for repo-scanner skill.

Detects Trojan Source (bidi overrides), homoglyph attacks (mixed Cyrillic/Greek/Latin),
zero-width characters, invisible control characters, and other encoding-based attacks
that grep/ripgrep cannot reliably catch.

Usage: python3 unicode_scanner.py <target-path>
"""

import os
import sys
import json

# Suspicious unicode ranges — characters that have no business being in source code
RANGES = [
    (0x0000, 0x0008),   # C0 controls (NUL through BS)
    (0x000E, 0x001F),   # C0 controls (SO through US)
    (0x007F, 0x007F),   # DEL
    (0x00AD, 0x00AD),   # Soft hyphen — invisible in most renderers
    (0x034F, 0x034F),   # Combining grapheme joiner
    (0x061C, 0x061C),   # Arabic letter mark
    (0x115F, 0x1160),   # Hangul fillers
    (0x17B4, 0x17B5),   # Khmer inherent vowels (invisible)
    (0x180E, 0x180E),   # Mongolian vowel separator
    (0x200B, 0x200F),   # Zero-width space, ZWNJ, ZWJ, LRM, RLM
    (0x2028, 0x2029),   # Line separator, paragraph separator
    (0x202A, 0x202E),   # Bidi overrides (LRE, RLE, PDF, LRO, RLO)
    (0x2060, 0x2064),   # Word joiner, invisible times/separator/plus
    (0x2066, 0x2069),   # Bidi isolates (LRI, RLI, FSI, PDI)
    (0x3164, 0x3164),   # Hangul filler
    (0xFE00, 0xFE0F),   # Variation selectors
    (0xFEFF, 0xFEFF),   # BOM / zero-width no-break space
    (0xFFF0, 0xFFF8),   # Specials
    (0xE0001, 0xE007F), # Tag characters (invisible language tags)
]

# Script ranges for homoglyph detection
CYRILLIC = set(range(0x0400, 0x04FF + 1))
GREEK = set(range(0x0370, 0x03FF + 1))

# High-risk bidi characters that enable Trojan Source attacks
TROJAN_SOURCE = set(range(0x202A, 0x202E + 1)) | set(range(0x2066, 0x2069 + 1))

# Source file extensions to scan
SOURCE_EXTS = {
    '.md', '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.json', '.yml',
    '.yaml', '.toml', '.py', '.rb', '.go', '.rs', '.java', '.kt', '.swift',
    '.sh', '.bash', '.zsh', '.fish', '.ps1', '.bat', '.cmd', '.xml', '.html',
    '.htm', '.css', '.scss', '.less', '.sql', '.graphql', '.proto', '.tf',
    '.hcl', '.dockerfile', '.env', '.cfg', '.ini', '.conf', '.lock', '.txt',
    '.c', '.h', '.cpp', '.hpp', '.cs', '.php', '.pl', '.lua', '.r', '.m',
    '.vue', '.svelte', '.astro',
}


def is_suspicious(ch):
    cp = ord(ch)
    for lo, hi in RANGES:
        if lo <= cp <= hi:
            return True
    return False


def is_trojan_source(ch):
    return ord(ch) in TROJAN_SOURCE


def has_mixed_script(line):
    """Detect lines mixing Latin with Cyrillic or Greek — potential homoglyph attack."""
    has_latin = any('a' <= c.lower() <= 'z' for c in line)
    has_cyrillic = any(ord(c) in CYRILLIC for c in line)
    has_greek = any(ord(c) in GREEK for c in line)
    return (has_latin and has_cyrillic) or (has_latin and has_greek)


def should_scan(filename):
    ext = os.path.splitext(filename)[1].lower()
    if ext in SOURCE_EXTS:
        return True
    # Also scan extensionless files (could be scripts)
    if '.' not in filename:
        return True
    return False


def scan_file(filepath, target):
    findings = []
    rel = os.path.relpath(filepath, target)
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as fh:
            for lineno, line in enumerate(fh, 1):
                for col, ch in enumerate(line):
                    if is_suspicious(ch):
                        severity = "CRITICAL" if is_trojan_source(ch) else "HIGH"
                        char_name = f"U+{ord(ch):04X}"
                        findings.append({
                            "severity": severity,
                            "type": "TROJAN_SOURCE" if is_trojan_source(ch) else "HIDDEN_CHAR",
                            "file": rel,
                            "line": lineno,
                            "col": col,
                            "codepoint": char_name,
                            "context": line.rstrip()[:120]
                        })
                if has_mixed_script(line):
                    findings.append({
                        "severity": "HIGH",
                        "type": "MIXED_SCRIPT",
                        "file": rel,
                        "line": lineno,
                        "col": None,
                        "codepoint": None,
                        "context": line.rstrip()[:120]
                    })
    except (PermissionError, OSError):
        pass
    return findings


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else '.'

    if not os.path.exists(target):
        print(json.dumps({"error": f"Path not found: {target}"}))
        sys.exit(1)

    all_findings = []
    files_scanned = 0

    for root, dirs, files in os.walk(target):
        # Skip .git directory
        dirs[:] = [d for d in dirs if d != '.git']
        for f in files:
            if should_scan(f):
                filepath = os.path.join(root, f)
                files_scanned += 1
                all_findings.extend(scan_file(filepath, target))

    result = {
        "files_scanned": files_scanned,
        "total_findings": len(all_findings),
        "critical": len([f for f in all_findings if f["severity"] == "CRITICAL"]),
        "high": len([f for f in all_findings if f["severity"] == "HIGH"]),
        "findings": all_findings[:100],  # Cap output at 100 findings
        "truncated": len(all_findings) > 100
    }

    if all_findings:
        # Human-readable summary first
        print(f"ALERT: {len(all_findings)} suspicious unicode finding(s) in {files_scanned} files")
        for f in all_findings[:20]:
            loc = f"{f['file']}:{f['line']}"
            if f['col'] is not None:
                loc += f":{f['col']}"
            print(f"  [{f['severity']}] {f['type']} at {loc} {f.get('codepoint', '')}")
        if len(all_findings) > 20:
            print(f"  ... and {len(all_findings) - 20} more")
        print()

    else:
        print(f"CLEAN: No suspicious unicode in {files_scanned} files scanned")

    # Also output JSON for programmatic consumption
    print("---JSON---")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
