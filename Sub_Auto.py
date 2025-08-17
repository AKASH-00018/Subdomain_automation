import subprocess
import os
import re
import time

def run_command(command, error_message):
    """
    Executes a shell command and captures its output.
    Returns (stdout, stderr, returncode).
    """
    try:
        process = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            check=False  # Do not raise an exception for non-zero exit codes
        )
        if process.returncode != 0 and "not found" in process.stderr.lower():
            print(f"🚨 Error: {error_message}. Please ensure it is installed and in your system's PATH.")
            return None, process.stderr, process.returncode
        return process.stdout, process.stderr, process.returncode
    except FileNotFoundError:
        print(f"🚨 Error: Command '{command.split(' ')[0]}' not found. Please ensure it is installed and in your system's PATH.")
        return None, "FileNotFoundError", 127
    except Exception as e:
        print(f"🚨 An unexpected error occurred: {e}")
        return None, str(e), 1

def find_subdomains(target_domain):
    """
    Discovers subdomains using subfinder and amass, removes duplicates,
    performs recursive discovery (one level), and checks for live subdomains.
    """
    print(f"\n🚀 Starting subdomain discovery for {target_domain}...")
    unique_subdomains = set()
    initial_subdomain_files = []

    # --- Step 1: Initial Subdomain Discovery ---
    tools = {
        "subfinder": f"subfinder -d {target_domain} -o {target_domain}_subfinder.txt",
        "amass": f"amass enum -d {target_domain} -o {target_domain}_amass.txt"
    }

    print("\n--- Running initial subdomain tools (subfinder & amass) ---")
    for tool_name, command in tools.items():
        output_file = f"{target_domain}_{tool_name}.txt"
        initial_subdomain_files.append(output_file)
        print(f"  Running {tool_name}...")
        stdout, stderr, returncode = run_command(command, f"Tool '{tool_name}'")

        if returncode == 0 and os.path.exists(output_file):
            print(f"  {tool_name} completed. Results saved to {output_file}")
            with open(output_file, 'r') as f:
                for line in f:
                    unique_subdomains.add(line.strip())
        else:
            print(f"  {tool_name} failed or produced no output file. Error: {stderr.strip()}")
            if "not found" in stderr.lower():
                return None # Tool not found, cannot proceed

    # Add the target domain itself to the list to ensure it's checked
    unique_subdomains.add(target_domain)

    print(f"\n✨ Found {len(unique_subdomains)} unique subdomains initially.")

    # --- Step 2: Recursive Subdomain Finding (one level deep) ---
    print("\n--- Starting recursive subdomain discovery (one level) ---")
    newly_found_subdomains = set()
    subdomains_to_process_recursively = list(unique_subdomains.copy()) # Make a copy to iterate
    total_recursive_targets = len(subdomains_to_process_recursively)

    for i, sub in enumerate(subdomains_to_process_recursively):
        # Skip the main domain for recursive lookup to avoid redundant calls
        if sub == target_domain:
            continue

        progress_percentage = (i + 1) / total_recursive_targets * 100
        print(f"\r  Processing recursive target: {sub} ({progress_percentage:.2f}%)", end="", flush=True)

        # Use -o /dev/null to avoid creating many small files, we'll capture stdout
        subfinder_cmd = f"subfinder -d {sub}"
        amass_cmd = f"amass enum -d {sub}"

        stdout_subfinder, _, returncode_subfinder = run_command(subfinder_cmd, "subfinder")
        if returncode_subfinder == 0 and stdout_subfinder:
            for line in stdout_subfinder.splitlines():
                if line.strip():
                    newly_found_subdomains.add(line.strip())

        stdout_amass, _, returncode_amass = run_command(amass_cmd, "amass")
        if returncode_amass == 0 and stdout_amass:
            for line in stdout_amass.splitlines():
                if line.strip():
                    newly_found_subdomains.add(line.strip())
        time.sleep(0.1) # Small delay to avoid hammering the system

    print("\n") # Newline after progress bar
    unique_subdomains.update(newly_found_subdomains) # Add newly found ones
    print(f"\n🔄 After recursion, total unique subdomains: {len(unique_subdomains)}")

    temp_subdomain_file = f"{target_domain}_all_unique_subdomains.txt"
    with open(temp_subdomain_file, 'w') as f:
        for sub in sorted(list(unique_subdomains)):
            f.write(f"{sub}\n")

    # --- Step 3: Live Subdomain Check with httpx-toolkit ---
    print("\n--- Checking for live subdomains with httpx-toolkit ---")
    live_subdomains_file = f"{target_domain}_subdomains.txt"
    httpx_command = f"cat {temp_subdomain_file} | httpx -silent -o {live_subdomains_file}"

    stdout, stderr, returncode = run_command(httpx_command, "httpx-toolkit")

    if returncode == 0 and os.path.exists(live_subdomains_file):
        print(f"✅ Live subdomains identified and saved to {live_subdomains_file}")
        # Clean up temporary files
        for f in initial_subdomain_files:
            if os.path.exists(f):
                os.remove(f)
        if os.path.exists(temp_subdomain_file):
            os.remove(temp_subdomain_file)

        with open(live_subdomains_file, 'r') as f:
            live_count = len(f.readlines())
        print(f"📊 Total live subdomains found: {live_count}")
        return live_subdomains_file
    else:
        print(f"❌ httpx-toolkit failed or produced no output. Error: {stderr.strip()}")
        # Still clean up temp files even if httpx fails
        for f in initial_subdomain_files:
            if os.path.exists(f):
                os.remove(f)
        if os.path.exists(temp_subdomain_file):
            os.remove(temp_subdomain_file)
        return None

def screenshot_subdomains(target_domain):
    """
    Takes screenshots of live subdomains using eyewitness.
    """
    default_input_file = f"{target_domain}_subdomains.txt"
    input_file = input(f"\nEnter the path to the file containing live subdomains to screenshot (default: {default_input_file}): ").strip()
    if not input_file:
        input_file = default_input_file

    if not os.path.exists(input_file):
        print(f"🚨 Error: Input file '{input_file}' not found. Please ensure the path is correct.")
        return

    output_dir = f"screenshots_{target_domain}"
    print(f"\n📸 Starting screenshot process for domains in '{input_file}'...")
    print(f"   Screenshots will be saved to: {output_dir}")

    eyewitness_command = f"eyewitness -f {input_file} --web -d {output_dir}"
    stdout, stderr, returncode = run_command(eyewitness_command, "eyewitness")

    if returncode == 0:
        print(f"✅ Screenshotting completed successfully. Check the '{output_dir}' directory.")
    else:
        print(f"❌ Screenshotting failed. Error: {stderr.strip()}")
        if "not found" in stderr.lower():
            return # Tool not found, already reported by run_command

def main():
    """Main function to guide the user through the process."""
    print("Welcome to the Subdomain Automation Script! 🚀")
    print("This script helps you find subdomains, identify live ones, and take screenshots.")
    print("----------------------------------------------------------------------")

    target_domain = input("Please enter the target domain (e.g., example.com): ").strip()
    if not target_domain:
        print("Domain cannot be empty. Exiting.")
        return

    while True:
        print("\n--- Main Menu ---")
        print("1. Subdomain Finding & Live Check")
        print("2. Screenshotting Live Subdomains")
        print("3. Exit")

        choice = input("Enter your choice (1, 2, or 3): ").strip()

        if choice == '1':
            live_subdomains_file = find_subdomains(target_domain)
            if live_subdomains_file:
                print(f"\n🎉 Subdomain finding completed! Live subdomains saved to: {live_subdomains_file}")
            else:
                print("\n😔 Subdomain finding failed or no live subdomains were found.")
        elif choice == '2':
            screenshot_subdomains(target_domain)
            print("\n📸 Screenshotting process finished.")
        elif choice == '3':
            print("Exiting the script. Goodbye!  ")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()