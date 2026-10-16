# Collect fresh phishing-feed snapshots for temporal evaluation.
# GitHub-Actions-adapted: writes into ./snapshots/<YYYYMMDD_HHMMSS>/ (repo-relative).
# Sources: OpenPhish (URL feed) + phishing.army (domains) + CERT.pl (domains, fallback) + PhishTank CSV dump (keyless).
# Tranco is collected separately (static configured list) - intentionally NOT here.
# Daily 00:00 UTC via .github/workflows/collect.yml; each run commits one snapshot folder.

import json, os, urllib.request
from datetime import datetime, timezone

sys_encoding_fixed = False
try:
    import sys
    sys.stdout.reconfigure(encoding="utf-8")
    sys_encoding_fixed = True
except Exception:
    pass

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) thesis-collector/1.1"}

def fetch(url, timeout=60):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()

def main():
    # GitHub Actions / repo-local: ./snapshots. VPS: override with OUTROOT env.
    outroot = os.environ.get("OUTROOT") or os.path.join(os.getcwd(), "snapshots")
    run = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    d = os.path.join(outroot, run)
    os.makedirs(d, exist_ok=True)
    meta = {"snapshot_utc": run, "sources": {}}

    # --- OpenPhish (no key, plain-text URL feed) ---
    try:
        data = fetch("https://openphish.com/feed.txt").decode("utf-8", "replace")
        lines = [l.strip() for l in data.splitlines() if l.strip().startswith("http")]
        with open(os.path.join(d, "openphish.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        meta["sources"]["openphish"] = {"count": len(lines), "status": "ok"}
    except Exception as e:
        meta["sources"]["openphish"] = {"error": str(e)}

    # --- phishing.army (keyless domain blocklist, PhishTank replacement) ---
    try:
        data = fetch("https://phishing.army/download/phishing_army_blocklist_extended.txt").decode("utf-8", "replace")
        doms = [l.strip() for l in data.splitlines() if l.strip() and not l.startswith("#")]
        with open(os.path.join(d, "phishing_army_domains.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(doms))
        meta["sources"]["phishing_army"] = {"count": len(doms), "status": "ok"}
    except Exception as e:
        meta["sources"]["phishing_army"] = {"error": str(e)}

    # --- CERT.pl Phishing Database (keyless domain feed, fallback source) ---
    try:
        data = fetch("https://hole.cert.pl/domains/domains.txt").decode("utf-8", "replace")
        doms = [l.strip() for l in data.splitlines() if l.strip() and not l.startswith("#")]
        with open(os.path.join(d, "cert_pl_domains.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(doms))
        meta["sources"]["cert_pl"] = {"count": len(doms), "status": "ok"}
    except Exception as e:
        meta["sources"]["cert_pl"] = {"error": str(e)}

    # --- PhishTank public data dump (keyless CSV, refreshed hourly upstream) ---
    try:
        data = fetch("http://data.phishtank.com/data/online-valid.csv").decode("utf-8", "replace")
        lines = [l for l in data.splitlines() if l.strip()]
        with open(os.path.join(d, "phishtank_online_valid.csv"), "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        meta["sources"]["phishtank"] = {"count": max(0, len(lines) - 1), "status": "ok"}
    except Exception as e:
        meta["sources"]["phishtank"] = {"error": str(e)}

    with open(os.path.join(d, "snapshot_meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    print(json.dumps(meta, indent=2))

    # Fail the job (red) only if BOTH live sources failed - so silent breakage is visible.
    ok = [v for k, v in meta["sources"].items() if v.get("status") == "ok"]
    if not ok:
        raise SystemExit("all feed sources failed")

    # --- Optional upload to Google Drive via rclone (VPS mode) ---
    # Requires: rclone configured with a remote named "gdrive" (rclone config),
    # and GDRIVE_FOLDER env set to the destination folder path, e.g. "thesis-snapshots".
    gdrive_folder = os.environ.get("GDRIVE_FOLDER")
    if gdrive_folder:
        import subprocess
        try:
            subprocess.run(
                ["rclone", "copy", d, f"gdrive:{gdrive_folder}/{run}"],
                check=True, timeout=600,
            )
            meta["upload"] = {"target": f"gdrive:{gdrive_folder}/{run}", "status": "ok"}
            print("uploaded to gdrive:", gdrive_folder)
        except Exception as e:
            meta["upload"] = {"error": str(e), "status": "failed"}
            print("gdrive upload failed (snapshot kept locally):", e)
        with open(os.path.join(d, "snapshot_meta.json"), "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

if __name__ == "__main__":
    main()

