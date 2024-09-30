import sys
import pandas as pd
import os
import json
import re
import subprocess

def extract_commit_hash(patch_commit):
    """
    Extract the commit has from the patch_commit string.
    If it's an URL, extract the hash part from it.
    """

    #check if the pratch_commit contains a URL
    match = re.search(r'([a-fA-F0-9]{40})$', patch_commit)
    if match:
        return match.group(1)
    else:
        #if the commit hash is a valid SHA, return it as-is
        return patch_commit

def run_cve_search(patch_commit, dir_path):
    """
    Runs the cve_search script with the given commit SHA and returns the CVE if found.
    """
    try:
        # Run the cve_search script with the commit SHA
        cve_search_script = os.path.join(dir_path, "../deps/vulns/scripts/cve_search")
        result = subprocess.run([cve_search_script, patch_commit], capture_output=True, text=True)
        # Extract the CVE number using a regex pattern
        if result.returncode == 0:
            match = re.search(r'(CVE-\d{4}-\d+)', result.stdout)
            if match:
                return match.group(1)  # Return just the CVE number
        return None
    except Exception as e:
        print(f"Error running cve_search for {patch_commit}: {e}")
        return None

def create_json_and_mbox(row, output_dir, cve_number, commit_hash):
    #Extract the necessary columns from the row
    patch_commit = row['Patch commit']
    title = row['Title']
    subsystem = row['Subsystem / Driver / Feature']
    remote_local = row['Remote/local']
    dos_corrupt = row['DoS/corrupt']
    bug_class = row['Bug class']
    exploitation = row['Exploitation']
    priv_required = row['Privileges required']
    known_exploit = row['Known exploit']
    severity = row['Severity']
    live_patchable = row['Livepatchable']
    included = row['Included']
    notes = row['Notes']

    # Create the JSON content
    cve_data = {
            "cve_number": cve_number if cve_number else "None",
            "patch_commit": commit_hash,
            "title": title,
            "subsystem": subsystem,
            "remote_local": remote_local,
            "impact": dos_corrupt,
            "bug_class": bug_class,
            "exploitation": exploitation,
            "priviledge_required": priv_required,
            "known_exploit": known_exploit,
            "severity": severity,
            "live_patchable": live_patchable,
            "included": included,
            "notes": notes
    }

    # Create JSON file
    json_file = os.path.join(output_dir, f"{commit_hash}.json")
    with open(json_file, 'w') as jf:
        json.dump(cve_data, jf, indent=4)

    # Optionally creaet MBOX file
    mbox_file = os.path.join(output_dir, f"{commit_hash}.mbox")
    with open(mbox_file, 'w') as mf:
        mf.write(f"From: Cloud LTS Submission <clts@blah.org>\n")
        mf.write(f"To: clts@blah.org\n")
        mf.write(f"Subject: Submission for {patch_commit}\n\n")
        mf.write(f"Subject: CVE Submission for {patch_commit}\n\n")
        mf.write(f"CVE Number: {cve_number if cve_number else 'None'}\n")
        mf.write(f"Title: {title}\n")
        mf.write(f"Subsystem/Driver/Feature: {subsystem}\n")
        mf.write(f"Remote/Local: {remote_local}\n")
        mf.write(f"Impact: {dos_corrupt}\n")
        mf.write(f"Bug Class: {bug_class}\n")
        mf.write(f"Exploitation Details: {exploitation}\n")
        mf.write(f"Privileges Required: {priv_required}\n")
        mf.write(f"Known Exploit: {known_exploit}\n")
        mf.write(f"Severity: {severity}\n")
        mf.write(f"Live-Patchable: {live_patchable}\n")
        mf.write(f"Included: {included}\n")
        mf.write(f"Notes: {notes}\n")

def main():
    if len(sys.argv) != 3:
        print("Usage: create_commit.py <KERNEL_VERSION> <EXLS SHEET>")
        sys.exit(1)

    kernel_version = sys.argv[1]
    excel_file = sys.argv[2]

    #Load the Excel file
    try:
        xl = pd.ExcelFile(excel_file)
    except FileNotFoundError:
        print(f"Error: Excel file {excel_file} not found.")
        sys.exit(1)

    # Check if the kernel version (sheet) exits
    if kernel_version not in xl.sheet_names:
        print(f"Error: No tab found for kernel version {kernel_version}")
        sys.exit(1)

    # Read the sheet for the kernel version
    df = xl.parse(kernel_version)

    # Ensure the required columns are present
    required_columns = ['Patch commit', 'Title', 'Subsystem / Driver / Feature', 'Remote/local',
                        'DoS/corrupt', 'Bug class', 'Exploitation', 'Privileges required',
                        'Known exploit', 'Severity', 'Livepatchable', 'Included', 'Notes']

    if not all(col in df.columns for col in required_columns):
        print(f"Error: Missing required columns in sheet {kernel_version}")
        sys.exit(1)

    # Get the directory where the script is located
    script_dir = os.path.dirname(os.path.realpath(__file__))
    work_dir = os.path.dirname(script_dir)

    # Create output directory if it doesn't exist
    output_dir = os.path.join(work_dir, f"cve/{kernel_version}/")
    os.makedirs(output_dir, exist_ok=True)

    # Process each row and create a JSON and MBOX file
    for _, row in df.iterrows():
        # Extract commit hash from Patch commit column (could be URL or raw SHA)
        patch_commit = row['Patch commit']
        commit_hash = extract_commit_hash(patch_commit)

        # Run cve_search to check if a CVE exists for the patch commit
        dir_path = os.path.dirname(os.path.realpath(__file__))  # Get current script directory
        cve_number = run_cve_search(commit_hash, dir_path)

        # Create the JSON and MBOX files with the CVE information
        create_json_and_mbox(row, output_dir, cve_number, commit_hash)

    print(f"JSON and MBOX files created for kernel version {kernel_version} in {output_dir}")

if __name__ == "__main__":
    main()

