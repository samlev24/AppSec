import os
import re

SECRET_PATTERNS = [
    r"API_KEY\s*=\s*['"]?[A-Za-z0-9_\-]{8,}['"]?",
    r"SECRET\s*=\s*['"]?[A-Za-z0-9_\-]{8,}['"]?",
    r"token\s*[:=]\s*['"]?[A-Za-z0-9_\-]{8,}['"]?",
]

def scan_for_secrets(base_path):
    findings = []
    for root, _, files in os.walk(base_path):
        for file in files:
            if file.endswith(('.py', '.js', '.env', '.txt', '.json')):
                filepath = os.path.join(root, file)
                with open(filepath, "r", errors="ignore") as f:
                    for i, line in enumerate(f, 1):
                        for pattern in SECRET_PATTERNS:
                            if re.search(pattern, line):
                                findings.append((filepath, i, line))
    return findings
