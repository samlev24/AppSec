# appsec-toolkit/scanner.py
import argparse
from checks import secrets, headers # Import the new headers module

def main():
    parser = argparse.ArgumentParser(description="AppSec Toolkit: Scan a project for security issues.")
    parser.add_argument("--path", help="Path to the source code directory to scan for secrets")
    parser.add_argument("--url", help="URL to check for security headers")
    # Potentially add a mutually exclusive group here if only one action is desired at a time,
    # or allow both to run if specified. For now, let's allow both.

    args = parser.parse_args()

    if not args.path and not args.url:
        parser.print_help()
        print("\nError: You must specify either --path or --url.")
        return

    if args.path:
        print(f"🔍 Scanning {args.path} for secrets...\n")
        secret_findings = secrets.scan_for_secrets(args.path)

        if secret_findings:
            print("🚨 Potential secrets found:")
            for file, line_no, content in secret_findings:
                print(f"  {file}:{line_no} → {content.strip()}")
        else:
            print("✅ No secrets found in the specified path!")
        print("-" * 40) # Separator

    if args.url:
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
        print("-" * 40) # Separator

if __name__ == "__main__":
    main()
