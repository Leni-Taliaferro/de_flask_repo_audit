import os
import shutil
import subprocess
import sys
from pathlib import Path

# ==========================================
# CONFIGURATION
# ==========================================
# Add any internal/private packages that shouldn't be checked on PyPI
INTERNAL_PACKAGES = ["barklion"]

# Optional: Set these if you want to inspect a deployed Cloud Run image
GCP_PROJECT = os.environ.get("PROJECT", "")
GCP_SERVICE = os.environ.get("SERVICE_NAME", "")
GCP_REGION = os.environ.get("REGION", "us-central1")


def get_container_engine():
    """Detect whether Podman or Docker is installed."""
    if shutil.which("podman"):
        return "podman"
    elif shutil.which("docker"):
        return "docker"
    return None


def run_command(cmd, outfile=None, text_input=None):
    """Safely execute a system command and log output."""
    res = subprocess.run(cmd, input=text_input, capture_output=True, text=True)
    combined_output = f"{res.stdout}\n{res.stderr}".strip()
    if outfile:
        with open(outfile, "w", encoding="utf-8") as f:
            f.write(combined_output)
    return res.returncode, combined_output


def filter_requirements(input_path, output_path):
    """Filter out comments, blank lines, and internal private packages."""
    if not Path(input_path).exists():
        print(f" Requirements file {input_path} not found.")
        return False

    with open(input_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    public_lines = []
    for line in lines:
        cleaned = line.strip()
        if not cleaned or cleaned.startswith("#"):
            continue

        # Extract base package name
        pkg_name = (
            cleaned.split("==")[0]
            .split(">=")[0]
            .split("<=")[0]
            .split("~=")[0]
            .strip()
            .lower()
        )

        if pkg_name in [p.lower() for p in INTERNAL_PACKAGES]:
            print(f" Filtered internal package: {cleaned}")
            continue
        public_lines.append(cleaned)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(public_lines) + "\n")

    return True


def audit_single_requirements(engine, req_file_path, service_tag):
    """Run vulnerability and compatibility checks for a single requirements file."""
    print(f"\n----------------------------------------")
    print(f" AUDITING SERVICE / FOLDER: [{service_tag}]")
    print(f" Path: {req_file_path.relative_to(Path.cwd())}")
    print(f"----------------------------------------")

    pub_req_file = f"public_requirements_{service_tag}.txt"
    has_public_reqs = filter_requirements(req_file_path, pub_req_file)

    if not has_public_reqs:
        return

    # Check 1: Python Version Check
    ver_file = f"python_version_{service_tag}.txt"
    run_command(
        [engine, "run", "--rm", "docker.io/library/python:3.14-slim", "python", "--version"],
        outfile=ver_file,
    )

    # Check 2: Vulnerability Check (pip-audit)
    print(" Running security vulnerability check (pip-audit)...")
    vuln_file = f"vulnerabilities_{service_tag}.txt"
    audit_cmd = [
        engine,
        "run",
        "--rm",
        "-v",
        f"{Path.cwd()}:/workspace",
        "-w",
        "/workspace",
        "docker.io/library/python:3.9-slim",
        "sh",
        "-c",
        f"pip install --quiet pip-audit && pip-audit -r {pub_req_file}",
    ]
    run_command(audit_cmd, outfile=vuln_file)

    # Check 3: Python 3.14 Compatibility Check
    print(" Running Python 3.14 dry-run compatibility check...")
    compat_file = f"compatibility_{service_tag}.txt"
    compat_cmd = [
        engine,
        "run",
        "--rm",
        "-v",
        f"{Path.cwd()}:/workspace",
        "-w",
        "/workspace",
        "docker.io/library/python:3.14-slim",
        "pip",
        "install",
        "--dry-run",
        "-r",
        pub_req_file,
    ]
    run_command(compat_cmd, outfile=compat_file)

    print(f" Completed [{service_tag}] -> Artifacts: {compat_file}, {vuln_file}")


def main():
    print("========================================")
    print(" MULTI-SERVICE REPO AUDITOR")
    print("========================================\n")

    engine = get_container_engine()
    if not engine:
        print(" Error: Neither Podman nor Docker was found in PATH.")
        sys.exit(1)
    print(f" Container Engine detected: {engine}")

    # Mode A: Inspect a specific Cloud Run container
    if GCP_PROJECT and GCP_SERVICE:
        print(f"\n Cloud Run Mode: Inspecting {GCP_SERVICE} in {GCP_PROJECT}...")

        get_img_cmd = [
            "gcloud",
            "run",
            "services",
            "describe",
            GCP_SERVICE,
            f"--region={GCP_REGION}",
            f"--project={GCP_PROJECT}",
            '--format="value(spec.template.spec.containers[0].image)"',
        ]
        _, img_url = run_command(get_img_cmd)
        container_img = img_url.strip().strip('"')

        service_tag = f"{GCP_PROJECT}_{GCP_SERVICE}"
        raw_req_file = Path(f"requirements_from_container_{service_tag}.txt")

        print(" Fetching live container pip freeze...")
        run_command(
            [engine, "run", "--rm", container_img, "pip", "freeze"],
            outfile=str(raw_req_file),
        )
        audit_single_requirements(engine, raw_req_file, service_tag)

    # Mode B: Scan local repository for all requirements.txt files
    else:
        print("\n Local Repo Mode: Searching workspace for requirements files...")
        req_files = list(Path.cwd().rglob("requirements.txt"))
        req_files = [
            f
            for f in req_files
            if not any(
                p.startswith(".") or "venv" in p or "node_modules" in p
                for p in f.parts
            )
        ]

        if not req_files:
            print(" No requirements.txt files found in workspace!")
            sys.exit(1)

        print(f" Found {len(req_files)} requirements file(s):")
        for f in req_files:
            print(f"  - {f.relative_to(Path.cwd())}")

        for req_file in req_files:
            # Tag the output files by parent folder (e.g. hubspot, reception, tickethook)
            folder_tag = req_file.parent.name if req_file.parent != Path.cwd() else "root"
            audit_single_requirements(engine, req_file, folder_tag)

    print("\n========================================")
    print(" ALL AUDITS COMPLETE! Check for new txt files")
    print("========================================")


if __name__ == "__main__":
    main()
