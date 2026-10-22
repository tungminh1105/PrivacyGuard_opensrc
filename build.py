"""Packaging script for PrivacyGuard using PyInstaller (Phase F).

Compiles the unified PrivacyGuard CLI and Sysmon Collector into a standalone
executable for Windows deployment.

Usage:
    python build.py [--onefile | --onedir] [--clean]
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys


def run_pyinstaller_build(onefile: bool = True, clean: bool = True) -> int:
    """Invoke PyInstaller to package PrivacyGuard CLI into dist/."""
    project_root = os.path.dirname(os.path.abspath(__file__))

    # Clean existing build artifacts if requested
    if clean:
        for folder in ["build", "dist"]:
            p = os.path.join(project_root, folder)
            if os.path.exists(p):
                print(f"[*] Cleaning {p}...")
                shutil.rmtree(p, ignore_errors=True)

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--name",
        "privacyguard",
        "--add-data",
        f"config.yaml{os.pathsep}.",
        "--hidden-import",
        "psutil",
        "--hidden-import",
        "yaml",
        "--hidden-import",
        "networkx",
        "--hidden-import",
        "sklearn",
        "--hidden-import",
        "torch",
        "--hidden-import",
        "win32evtlog",
        "--hidden-import",
        "win32api",
        "--hidden-import",
        "win32con",
        "--console",
    ]

    if onefile:
        cmd.append("--onefile")
    else:
        cmd.append("--onedir")

    cmd.append(os.path.join(project_root, "cli.py"))

    print("\n" + "=" * 60)
    print("           BUILDING PRIVACYGUARD STANDALONE EXECUTABLE")
    print("=" * 60)
    print("Executing command:")
    print(" ".join(cmd))
    print("-" * 60)

    res = subprocess.run(cmd, cwd=project_root)
    if res.returncode == 0:
        dist_path = os.path.join(project_root, "dist")
        print("\n" + "=" * 60)
        print(f"[+] Build successful! Output located in: {dist_path}")
        if onefile:
            exe_file = os.path.join(dist_path, "privacyguard.exe")
            if os.path.exists(exe_file):
                size_mb = os.path.getsize(exe_file) / (1024 * 1024)
                print(f"[+] Standalone binary: {exe_file} ({size_mb:.2f} MB)")
        print("=" * 60 + "\n")
    else:
        print(f"\n[-] PyInstaller failed with exit code {res.returncode}")

    return res.returncode


def main():
    parser = argparse.ArgumentParser(description="PrivacyGuard Packaging Script")
    parser.add_argument("--onedir", action="store_true", help="Build as directory instead of single file")
    parser.add_argument("--no-clean", action="store_true", help="Do not clean build/dist folders before building")
    args = parser.parse_args()

    ret = run_pyinstaller_build(onefile=not args.onedir, clean=not args.no_clean)
    sys.exit(ret)


if __name__ == "__main__":
    main()
