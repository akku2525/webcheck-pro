"""
WebCheck Pro - Screenshot Module
Author: Akash Mishra

Captures a visual screenshot of the target using headless Chromium/Chrome
via subprocess (no selenium/playwright dependency needed - just the
browser binary, which is already on most Kali installs or a single
`apt install chromium` away).
"""

import base64
import os
import shutil
import subprocess
import tempfile

CANDIDATE_BINARIES = [
    "chromium-browser", "chromium", "google-chrome", "google-chrome-stable",
    "chrome", "brave-browser",
]

MAX_EMBED_BYTES = 3 * 1024 * 1024  # don't bloat the HTML report past ~3MB image


def find_browser_binary():
    for name in CANDIDATE_BINARIES:
        path = shutil.which(name)
        if path:
            return path
    return None


def capture_screenshot(url: str, timeout: int = 25, width: int = 1366, height: int = 850):
    binary = find_browser_binary()
    if not binary:
        return {
            "error": "No headless Chromium/Chrome binary found on PATH. "
                     "Install one with: sudo apt install chromium (Kali/Debian) "
                     "or sudo apt install chromium-browser."
        }

    tmp_dir = tempfile.mkdtemp(prefix="webcheckpro_")
    out_path = os.path.join(tmp_dir, "screenshot.png")

    cmd = [
        binary,
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--hide-scrollbars",
        "--disable-extensions",
        "--ignore-certificate-errors",
        f"--window-size={width},{height}",
        f"--screenshot={out_path}",
        "--virtual-time-budget=8000",
        url,
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
        if not os.path.exists(out_path):
            stderr = proc.stderr.decode(errors="ignore")[:400]
            return {"error": f"Screenshot capture failed. {stderr or 'No output file produced.'}"}

        size = os.path.getsize(out_path)
        if size == 0:
            return {"error": "Screenshot file was empty."}
        if size > MAX_EMBED_BYTES:
            return {"error": f"Screenshot too large to embed ({size // 1024} KB)."}

        with open(out_path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode("ascii")

        return {"base64_png": b64, "size_bytes": size, "browser_used": os.path.basename(binary)}
    except subprocess.TimeoutExpired:
        return {"error": f"Screenshot timed out after {timeout}s (site may be slow or blocking headless browsers)."}
    except Exception as e:
        return {"error": str(e)}
    finally:
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass
