"""
test_simulation.py
──────────────────
Local test runner for the Wazuh Browser History Monitor.

Validates that the monitoring script will work correctly on a Windows endpoint
BEFORE deployment — including under SYSTEM context (Wazuh agent service account).

Usage — normal user context:
    python test_simulation.py

Usage — SYSTEM context (simulates Wazuh agent, requires PsExec):
    psexec.exe -s "C:\\Program Files\\Python314\\python.exe" test_simulation.py

All 5 tests must pass in SYSTEM context before sharing with users.
"""

import os
import sys
import io
import json
import shutil
import sqlite3
import subprocess
import tempfile
import platform
import getpass
import datetime

# ── Force UTF-8 output (required under SYSTEM context) ───────────────────────
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ── Output helpers ────────────────────────────────────────────────────────────
def ok(msg):   print(f"  [PASS] {msg}")
def fail(msg): print(f"  [FAIL] {msg}")
def warn(msg): print(f"  [WARN] {msg}")
def section(title):
    print(f"\n{'-'*55}\n  {title}\n{'-'*55}")


# ─────────────────────────────────────────────────────────
# TEST 1 — Context / Identity
# ─────────────────────────────────────────────────────────
def test_context():
    section("TEST 1 - Who is running this script?")
    current_user = getpass.getuser()
    print(f"  Running as  : {current_user}")
    is_system = current_user.upper() in ("SYSTEM", "NT AUTHORITY\\SYSTEM") or current_user.endswith("$")
    if is_system:
        warn("Running as SYSTEM - this is the Wazuh agent context.")
        warn("Browser history paths must be resolved via user enumeration.")
    else:
        ok(f"Running as normal user '{current_user}'.")
        print(f"  LOCALAPPDATA: {os.environ.get('LOCALAPPDATA', 'NOT SET')}")


# ─────────────────────────────────────────────────────────
# TEST 2 — User Resolution
# ─────────────────────────────────────────────────────────
def test_user_resolution() -> list:
    section("TEST 2 - Logged-in user detection")

    users_from_query = []
    try:
        out = subprocess.check_output(
            ["query", "session"], stderr=subprocess.DEVNULL
        ).decode("utf-8", errors="ignore")
        for line in out.splitlines():
            if "Active" in line:
                parts = line.split()
                if len(parts) >= 2:
                    users_from_query.append(parts[1])
        if users_from_query:
            ok(f"query session found: {users_from_query}")
        else:
            warn("query session returned no Active sessions.")
    except Exception as e:
        fail(f"query session unavailable (expected under SYSTEM on some systems): {e}")

    skip = {"Public", "Default", "Default User", "All Users"}
    try:
        users_from_dir = [
            d for d in os.listdir(r"C:\Users")
            if os.path.isdir(os.path.join(r"C:\Users", d)) and d not in skip
        ]
        ok(f"C:\\Users enumeration found: {users_from_dir}")
    except Exception as e:
        fail(f"C:\\Users enumeration failed: {e}")
        users_from_dir = []

    return list(set(users_from_query + users_from_dir))


# ─────────────────────────────────────────────────────────
# TEST 3 — Browser DB Access
# ─────────────────────────────────────────────────────────
BROWSERS = {
    "chrome": r"Google\Chrome\User Data\Default\History",
    "edge":   r"Microsoft\Edge\User Data\Default\History",
    "brave":  r"BraveSoftware\Brave-Browser\User Data\Default\History",
}

_CHROME_EPOCH = datetime.datetime(1601, 1, 1)

def chrome_ts_to_iso(ts):
    try:
        return (_CHROME_EPOCH + datetime.timedelta(microseconds=ts)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return "unknown"


def test_browser_access(users: list):
    section("TEST 3 - Browser history file access")
    found_any = False

    for user in users:
        appdata = os.path.join(r"C:\Users", user, "AppData", "Local")
        if not os.path.isdir(appdata):
            warn(f"AppData not accessible for user '{user}': {appdata}")
            continue

        for browser, rel in BROWSERS.items():
            db_path = os.path.join(appdata, rel)
            if not os.path.exists(db_path):
                print(f"  [    ] {browser:10} not installed for '{user}'")
                continue

            found_any = True
            print(f"\n  Found: {db_path}")

            # Direct open test
            try:
                conn = sqlite3.connect(db_path)
                conn.execute("SELECT count(*) FROM urls")
                conn.close()
                ok("Direct open succeeded (browser not running or not locked)")
            except sqlite3.OperationalError as e:
                warn(f"Direct open failed (expected if browser is open): {e}")

            # Copy-then-open test (production approach)
            tmp = os.path.join(tempfile.gettempdir(), f"test_{browser}_{user}.db")
            try:
                shutil.copy2(db_path, tmp)
                ok("File copy succeeded.")
            except PermissionError as e:
                fail(f"File copy FAILED - SYSTEM cannot read this path: {e}")
                continue
            except Exception as e:
                fail(f"File copy failed: {e}")
                continue

            try:
                conn = sqlite3.connect(tmp)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute(
                    "SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 5"
                )
                rows = cur.fetchall()
                conn.close()
                os.remove(tmp)

                if rows:
                    ok(f"Query succeeded - {len(rows)} recent row(s) (showing latest 5):")
                    for row in rows:
                        ts = chrome_ts_to_iso(row["last_visit_time"])
                        print(f"      [{ts}] {row['url'][:80]}")
                else:
                    warn("Query succeeded but no rows returned (browser history empty).")
            except sqlite3.DatabaseError as e:
                fail(f"SQLite query failed: {e}")
                try:
                    os.remove(tmp)
                except Exception:
                    pass

    if not found_any:
        fail("No browser history files found. Check user resolution or browser installation.")


# ─────────────────────────────────────────────────────────
# TEST 4 — Output File Write
# ─────────────────────────────────────────────────────────
def test_output_write():
    section("TEST 4 - Output file write (simulating Wazuh log path)")

    test_output = os.path.join(tempfile.gettempdir(), "wazuh_browser_test.log")
    test_state  = os.path.join(tempfile.gettempdir(), "wazuh_browser_state.json")

    sample_event = {
        "event":       "browser_history",
        "user":        getpass.getuser(),
        "browser":     "chrome",
        "url":         "https://example.com",
        "title":       "Example Domain",
        "visit_time":  "2026-05-15T09:37:13Z",
        "visit_count": 1,
        "source":      "browser-monitor",
    }

    try:
        with open(test_output, "a", encoding="utf-8") as f:
            f.write(json.dumps(sample_event) + "\n")
        ok(f"Log write succeeded: {test_output}")
    except Exception as e:
        fail(f"Log write failed: {e}")

    try:
        state = {"chrome:testuser": 13379207631000000}
        with open(test_state, "w", encoding="utf-8") as f:
            json.dump(state, f)
        ok(f"State file write succeeded: {test_state}")
    except Exception as e:
        fail(f"State file write failed: {e}")

    print(f"\n  Sample JSON output line:")
    print(f"  {json.dumps(sample_event)}")


# ─────────────────────────────────────────────────────────
# TEST 5 — Full Script Dry Run
# ─────────────────────────────────────────────────────────
def test_full_script():
    section("TEST 5 - Full script dry run (browser_monitor.py)")

    script_dir   = os.path.dirname(os.path.abspath(__file__))
    monitor_path = os.path.join(script_dir, "browser_monitor.py")

    if not os.path.exists(monitor_path):
        warn(f"browser_monitor.py not found at {monitor_path}. Place both files in the same directory.")
        return

    tmp_log   = os.path.join(tempfile.gettempdir(), "wazuh_monitor_test.log")
    tmp_state = os.path.join(tempfile.gettempdir(), "wazuh_monitor_state.json")

    # Clean up previous test run
    for f in [tmp_log, tmp_state]:
        try:
            os.remove(f)
        except Exception:
            pass

    env = os.environ.copy()
    env["BROWSER_MONITOR_OUTPUT"] = tmp_log
    env["BROWSER_MONITOR_STATE"]  = tmp_state
    env["PYTHONIOENCODING"]       = "utf-8"

    result = subprocess.run(
        [sys.executable, monitor_path],
        capture_output=True, text=True, env=env, encoding="utf-8", errors="replace"
    )

    if result.returncode == 0:
        ok("Script exited cleanly (return code 0).")
    else:
        fail(f"Script exited with code {result.returncode}.")

    if result.stderr:
        warn(f"STDERR: {result.stderr[:400]}")

    if os.path.exists(tmp_log):
        ok(f"Output log created: {tmp_log}")
        with open(tmp_log, encoding="utf-8") as f:
            lines = f.readlines()
        print(f"  Lines written: {len(lines)}")
        for line in lines[:6]:
            print(f"    {line.strip()[:120]}")
    else:
        fail("Output log was NOT created - script likely crashed before writing.")


# ─────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"\n{'='*55}")
    print(f"  Wazuh Browser Monitor - Local Test Simulation")
    print(f"  Python {sys.version.split()[0]}  |  {platform.node()}")
    print(f"{'='*55}")

    test_context()
    users = test_user_resolution()
    test_browser_access(users)
    test_output_write()
    test_full_script()

    print(f"\n{'='*55}")
    print(f"  Simulation complete.")
    print(f"  Fix any [FAIL] items before deploying to endpoints.")
    print(f"  Run again with PsExec -s to validate SYSTEM context.")
    print(f"{'='*55}\n")
