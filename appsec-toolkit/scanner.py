# appsec-toolkit/scanner.py
import argparse
from checks import secrets, headers, debug_mode, dependencies # Import the new dependencies module

def main():
    parser = argparse.ArgumentParser(description="AppSec Toolkit: Scan a project for security issues.")
    parser.add_argument("--path", help="Path to the source code directory to scan")
    parser.add_argument("--url", help="URL to check for security headers")
    # Future: Add --skip-audit or --skip-secrets etc.

    args = parser.parse_args()

    if not args.path and not args.url:
        parser.print_help()
        print("\nError: You must specify either --path or --url.")
        return

    if args.path:
        # Secrets Scan
        print(f"🔍 Scanning {args.path} for secrets...\n")
        secret_findings = secrets.scan_for_secrets(args.path)
        if secret_findings:
            print("🚨 Potential secrets found:")
            for file, line_no, content in secret_findings:
                print(f"  {file}:{line_no} → {content.strip()}")
        else:
            print("✅ No secrets found in the specified path!")
        print("-" * 40)

        # Debug Mode Scan
        print(f"🔍 Scanning {args.path} for debug mode settings...\n")
        debug_findings = debug_mode.scan_for_debug_settings(args.path)
        if debug_findings:
            print("🚨 Potential debug/development settings found:")
            for finding in debug_findings:
                print(f"  📄 File: {finding['file']}")
                print(f"  ➡️ Line {finding['line']}: {finding['finding']}")
                print(f"  💡 Type: {finding['type']}\n")
        else:
            print("✅ No obvious debug/development settings found in the specified path!")
        print("-" * 40)

        # Dependency Vulnerability Scan
        print(f"🔍 Checking for vulnerable dependencies in {args.path} (requires requirements.txt and pip-audit)...\n")
        dep_results = dependencies.check_dependencies(args.path)
        
        if dep_results.get("error"):
            print(f"🚨 Error during dependency check: {dep_results['error']}")
        elif not dep_results.get("vulnerabilities"): # Check if the key exists and is empty
            # This handles both "success" message from check_dependencies and empty "vulnerabilities" list
            success_msg = dep_results.get("success", "✅ No vulnerable dependencies found.")
            print(success_msg)
        else: # Vulnerabilities found
            print("🚨 Vulnerable dependencies found:")
            for vuln in dep_results["vulnerabilities"]:
                print(f"  📦 Package: {vuln.get('package', 'N/A')}@{vuln.get('version', 'N/A')}")
                print(f"     ID: {vuln.get('vuln_id', 'N/A')}")
                print(f"     Description: {vuln.get('description', 'N/A')}")
                fix_versions = vuln.get('fix_versions', [])
                if fix_versions:
                    print(f"     Fix Versions: {', '.join(fix_versions)}")
                print("     " + "-" * 5) # Indented separator
        print("-" * 40)


    if args.url:
        # Header Check
        print(f"🔍 Checking security headers for {args.url}...\n")
        header_results = headers.check_security_headers(args.url)
        if header_results.get("error"):
            print(f"🚨 Error: {header_results['error']}")
        else:
            if header_results["found_headers"]:
                print("✅ Found Headers:")
                for header, value in header_results["found_headers"].items():
                    print(f"  {header}: {value}")
            else:
                print("ℹ️ No common security headers explicitly found.")
            
            if header_results["missing_headers"]:
                print("\n⚠️ Missing Headers & Recommendations:")
                for header, advice in header_results["missing_headers"].items():
                    print(f"  - {header}: {advice}")
            else:
                print("\n🎉 All common security headers checked are present or no issues found!")
        print("-" * 40)

if __name__ == "__main__":
    main()
