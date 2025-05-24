import os
import re

# Common patterns indicating debug mode or development environment
# We'll look in .py files and .env files primarily.
PYTHON_DEBUG_PATTERNS = [
    re.compile(r"^\s*DEBUG\s*=\s*True", re.IGNORECASE),
    re.compile(r"^\s*FLASK_DEBUG\s*=\s*1", re.IGNORECASE),
    re.compile(r"^\s*FLASK_ENV\s*=\s*['"]development['"]\s*$", re.IGNORECASE),
    # Django specific settings.py often has DEBUG = True
    # For Django, also check if DJANGO_SETTINGS_MODULE might point to a dev settings file if possible,
    # but that's more complex. Sticking to direct DEBUG = True is a good start.
]

ENV_DEBUG_PATTERNS = [
    re.compile(r"^\s*DEBUG\s*=\s*True", re.IGNORECASE),
    re.compile(r"^\s*ENVIRONMENT\s*=\s*development", re.IGNORECASE),
    re.compile(r"^\s*APP_ENV\s*=\s*dev", re.IGNORECASE),
]

# Files to check
PYTHON_FILES = ('.py',)
ENV_FILES = ('.env', 'config.env') # Add other common .env file names if needed

def scan_for_debug_settings(base_path):
    """
    Scans files in the given base_path for common debug mode configurations.
    Returns a list of findings.
    """
    findings = []
    for root, _, files in os.walk(base_path):
        # Skip common virtual environment directories to speed up scanning
        if "venv" in root or "node_modules" in root or ".git" in root:
            continue

        for file in files:
            filepath = os.path.join(root, file)
            
            try:
                if file.endswith(PYTHON_FILES):
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        for i, line in enumerate(f, 1):
                            for pattern in PYTHON_DEBUG_PATTERNS:
                                if pattern.search(line):
                                    findings.append({
                                        "file": filepath,
                                        "line": i,
                                        "finding": line.strip(),
                                        "type": "Python Debug Setting"
                                    })
                elif file.endswith(ENV_FILES) or file in ENV_FILES: # Check specific filenames like '.env'
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        for i, line in enumerate(f, 1):
                            for pattern in ENV_DEBUG_PATTERNS:
                                if pattern.search(line):
                                    findings.append({
                                        "file": filepath,
                                        "line": i,
                                        "finding": line.strip(),
                                        "type": "Environment Config Debug Setting"
                                    })
            except Exception as e:
                # Silently ignore files that can't be opened or read, or log if needed
                # print(f"Could not read file {filepath}: {e}")
                pass # Or log this issue
                
    return findings

if __name__ == '__main__':
    # Example usage:
    # Create a dummy project structure for testing
    if not os.path.exists("temp_test_project"):
        os.makedirs("temp_test_project/subdir")
    
    with open("temp_test_project/app.py", "w") as f:
        f.write("import flask\n")
        f.write("DEBUG = True\n")
        f.write("SECRET_KEY = 'supersecret'\n")

    with open("temp_test_project/subdir/settings.py", "w") as f:
        f.write("# Django settings file\n")
        f.write("DEBUG = True # Important for development\n")
        
    with open("temp_test_project/.env", "w") as f:
        f.write("FLASK_ENV='development'\n")
        f.write("DATABASE_URL='...'\n")
        f.write("DEBUG=True\n") # Another debug flag

    with open("temp_test_project/production.py", "w") as f:
        f.write("DEBUG = False\n")
        
    print("🧪 Scanning for debug settings in ./temp_test_project/\n")
    debug_findings = scan_for_debug_settings("./temp_test_project")
    
    if debug_findings:
        print("🚨 Potential debug/development settings found:")
        for finding in debug_findings:
            print(f"  📄 File: {finding['file']}")
            print(f"  ➡️ Line {finding['line']}: {finding['finding']}")
            print(f"  💡 Type: {finding['type']}\n")
    else:
        print("✅ No obvious debug/development settings found.")
        
    # Clean up dummy project (optional)
    # import shutil
    # shutil.rmtree("temp_test_project")
