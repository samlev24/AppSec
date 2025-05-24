import subprocess
import json
import os

# It's good practice to specify the path to requirements.txt if not in the current dir
# For now, we assume it's in the base_path being scanned or the current working directory

def check_dependencies(project_path):
    """
    Checks for known vulnerabilities in project dependencies using pip-audit.
    pip-audit needs to be installed in the environment where this script runs.
    It looks for a requirements.txt file in the project_path.
    """
    findings = []
    requirements_file = os.path.join(project_path, "requirements.txt")

    if not os.path.exists(requirements_file):
        return {"error": "requirements.txt not found in the specified path.", "vulnerabilities": []}

    try:
        # Using --json for structured output, and -r for the requirements file.
        # We must ensure pip-audit is installed where this toolkit is run.
        # Consider adding error handling for pip-audit not being found.
        process = subprocess.run(
            ["pip-audit", "-r", requirements_file, "--json", "--strict"],
            capture_output=True,
            text=True,
            check=False # Don't raise exception on non-zero exit, parse output instead
        )
        
        # pip-audit exits with 0 if no vulnerabilities, non-zero if vulnerabilities found or error
        # stderr might contain warnings or actual errors from pip-audit itself
        if process.stderr and "Failed to create an ephemeral virtual environment" in process.stderr:
             # A common issue if virtualenv/pip are not fully set up or have permission issues
            return {"error": f"pip-audit failed to create virtual environment: {process.stderr.strip()}", "vulnerabilities": []}
        if process.stderr and process.returncode != 0 and not process.stdout: # Check for actual errors if no stdout
            return {"error": f"pip-audit execution error: {process.stderr.strip()}", "vulnerabilities": []}

        # If stdout is empty and return code is 0, it means no vulns found or pip-audit didn't run properly.
        # If stdout is empty and return code is non-zero, it might be an error not caught above.
        if not process.stdout.strip():
            if process.returncode == 0:
                 return {"success": "No vulnerabilities found by pip-audit.", "vulnerabilities": []}
            else:
                # Attempt to provide a more generic error if stderr was also empty but exited non-zero
                error_message = process.stderr.strip() if process.stderr.strip() else "pip-audit did not produce output and exited with an error."
                return {"error": error_message, "vulnerabilities": []}


        # pip-audit's JSON output is a list of dictionaries, one per vulnerable dependency.
        # If it's not a list, it might be an error message (though --json should prevent this for vulns)
        try:
            vulnerabilities_data = json.loads(process.stdout)
            if not isinstance(vulnerabilities_data, list):
                 # This case should ideally not happen with --json if vulns are found,
                 # but as a safeguard if pip-audit changes output format for errors in JSON.
                 return {"error": f"Unexpected JSON output format from pip-audit: {process.stdout}", "vulnerabilities": []}
            
            for vuln in vulnerabilities_data:
                findings.append({
                    "package": vuln.get("name", "N/A"),
                    "version": vuln.get("version", "N/A"),
                    "vuln_id": vuln.get("id", "N/A"),
                    "description": vuln.get("description", "No description available."),
                    "fix_versions": vuln.get("fix_versions", []),
                })
        except json.JSONDecodeError:
            # This means pip-audit output was not valid JSON.
            # Could be an error message from pip-audit not in JSON format.
            return {"error": f"Failed to decode JSON output from pip-audit. Output: {process.stdout}", "vulnerabilities": []}
            
    except FileNotFoundError:
        return {"error": "pip-audit command not found. Please ensure it is installed and in your PATH.", "vulnerabilities": []}
    except Exception as e:
        # Catch any other unexpected errors during the process.
        return {"error": f"An unexpected error occurred while running pip-audit: {str(e)}", "vulnerabilities": []}

    return {"vulnerabilities": findings}


if __name__ == '__main__':
    # For local testing, you'd need a sample project with a requirements.txt
    # And pip-audit installed.
    
    # 1. Create a dummy project for testing
    sample_project_path = "temp_dep_test_project"
    if not os.path.exists(sample_project_path):
        os.makedirs(sample_project_path)
    
    # 2. Create a sample requirements.txt with a known old/vulnerable package (for testing)
    #    Example: requests==2.20.0 has known vulnerabilities.
    #    (Make sure not to use a version that's *too* old or obscure, pick one listed on PyPI)
    #    For a real test, you'd use a package with a *real* past vulnerability.
    #    Let's use a hypothetical one for now, or a real one if pip-audit is set up.
    #    Using a version of 'requests' known to have vulns for testing.
    with open(os.path.join(sample_project_path, "requirements.txt"), "w") as f:
        f.write("requests==2.19.0\n") # Known to have vulnerabilities
        f.write("Django==1.0\n")      # Hypothetically very old

    print(f"🧪 Checking dependencies for project at: {sample_project_path}\n")
    # Ensure pip-audit is installed: pip install pip-audit
    
    results = check_dependencies(sample_project_path)
    
    if results.get("error"):
        print(f"🚨 Error: {results['error']}")
    elif not results["vulnerabilities"]:
        print("✅ No vulnerable dependencies found (or pip-audit found none).")
    else:
        print("🚨 Vulnerable dependencies found:")
        for vuln in results["vulnerabilities"]:
            print(f"  📦 Package: {vuln['package']}@{vuln['version']}")
            print(f"     ID: {vuln['vuln_id']}")
            print(f"     Description: {vuln['description']}")
            if vuln['fix_versions']:
                print(f"     Fix Versions: {', '.join(vuln['fix_versions'])}")
            print("-" * 10)
            
    # Clean up dummy project (optional)
    # import shutil
    # shutil.rmtree(sample_project_path)
