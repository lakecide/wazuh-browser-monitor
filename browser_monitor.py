"""
browser_monitor.py
──────────────────
Wazuh Browser History Monitor for Windows endpoints.

Designed to run as a single-execution script via the Wazuh command wodle.
The wodle handles scheduling (default: every 1 minute).
Runs correctly under SYSTEM context (Wazuh agent service account).

Supported browsers: Chrome, Edge, Brave
Output format: JSON (one event per line, consumed by Wazuh logcollector)
"""

import os
import sys
import json
import shutil
import sqlite3
import logging
import tempfile
import datetime
import subprocess
import socket

# ── Force UTF-8 output (required when running under SYSTEM context) ──────────
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ──────────────────────────────────────────────
# CONFIGURATION
# Paths can be overridden via environment variables for testing.
# ──────────────────────────────────────────────
OUTPUT_LOG  = os.environ.get(
    "BROWSER_MONITOR_OUTPUT",
    r"C:\Program Files (x86)\ossec-agent\shared\browser_history.log"
)
STATE_FILE  = os.environ.get(
    "BROWSER_MONITOR_STATE",
    r"C:\Program Files (x86)\ossec-agent\shared\browser_state.json"
)
MONITOR_TAG = "browser-monitor"

BROWSERS = {
    "chrome": r"Google\Chrome\User Data\Default\History",
    "edge":   r"Microsoft\Edge\User Data\Default\History",
    "brave":  r"BraveSoftware\Brave-Browser\User Data\Default\History",
}

# ──────────────────────────────────────────────
# LOGGING  (syslog-style, consumed by logcollector)
# ──────────────────────────────────────────────
os.makedirs(os.path.dirname(OUTPUT_LOG), exist_ok=True)

logging.basicConfig(
    filename=OUTPUT_LOG,
    level=logging.INFO,
    format="%(asctime)s %(hostname)s %(tag)s: %(message)s",
    datefmt="%b %d %H:%M:%S",
    encoding="utf-8",
)

class _ContextFilter(logging.Filter):
    def __init__(self):
        self.hostname = socket.gethostname()
        self.tag = MONITOR_TAG
    def filter(self, record):
        record.hostname = self.hostname
        record.tag = self.tag
        return True

_logger = logging.getLogger()
_logger.addFilter(_ContextFilter())

def log(event: dict):
    """Emit a JSON event line that Wazuh logcollector decodes."""
    _logger.info(json.dumps(event, ensure_ascii=True))


# ──────────────────────────────────────────────
# USER RESOLUTION  (works under SYSTEM context)
# ──────────────────────────────────────────────
def get_logged_in_users() -> list:
    """
    Returns a list of usernames with profiles in C:\\Users.
    Falls back to directory enumeration when query session is unavailable
    (common when running as SYSTEM on Windows Home editions).
    """
    users = []

    # Method A: query session (works on domain-joined / Pro endpoints)
    try:
        output = subprocess.check_output(
            ["query", "session"], stderr=subprocess.DEVNULL
        ).decode("utf-8", errors="ignore")
        for line in output.splitlines():
            if "Active" in line:
                parts = line.split()
                if len(parts) >= 2:
                    users.append(parts[1])
    except Exception:
        pass

    # Method B: C:\Users enumeration (universal fallback)
    if not users:
        skip = {"Public", "Default", "Default User", "All Users"}
        try:
            users = [
                d for d in os.listdir(r"C:\Users")
                if os.path.isdir(os.path.join(r"C:\Users", d)) and d not in skip
            ]
        except Exception:
            pass

    return users


def get_appdata_local(username: str) -> list:
    """Returns valid AppData\\Local paths for a given username."""
    candidates = [
        os.path.join(r"C:\Users", username, "AppData", "Local"),
    ]
    # Also include env var path when running as normal user (testing)
    env_path = os.environ.get("LOCALAPPDATA", "")
    if env_path and env_path not in candidates:
        candidates.append(env_path)
    return [p for p in candidates if os.path.isdir(p)]


# ──────────────────────────────────────────────
# STATE  (tracks last-collected timestamp per user per browser)
# ──────────────────────────────────────────────
def load_state() -> dict:
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(state: dict):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


# ──────────────────────────────────────────────
# CHROME EPOCH CONVERSION
# Chrome timestamps are microseconds since 1601-01-01
# ──────────────────────────────────────────────
_CHROME_EPOCH = datetime.datetime(1601, 1, 1)

def chrome_ts_to_iso(ts: int) -> str:
    try:
        return (_CHROME_EPOCH + datetime.timedelta(microseconds=ts)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return "unknown"


# ──────────────────────────────────────────────
# HISTORY COLLECTION
# ──────────────────────────────────────────────
def collect_history(db_path: str, last_ts: int) -> tuple:
    """
    Copies the SQLite DB to a temp file (avoids browser file lock),
    queries all rows newer than last_ts, returns (rows, max_timestamp).
    """
    rows = []
    max_ts = last_ts
    tmp = os.path.join(tempfile.gettempdir(), f"wazuh_bh_{os.getpid()}.db")

    try:
        shutil.copy2(db_path, tmp)
    except PermissionError as e:
        log({"event": "copy_error", "path": db_path, "error": str(e)})
        return rows, max_ts
    except FileNotFoundError:
        return rows, max_ts

    try:
        conn = sqlite3.connect(tmp)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            """
            SELECT url, title, last_visit_time, visit_count
            FROM urls
            WHERE last_visit_time > ?
            ORDER BY last_visit_time ASC
            """,
            (last_ts,),
        )
        for row in cur.fetchall():
            rows.append(dict(row))
            if row["last_visit_time"] > max_ts:
                max_ts = row["last_visit_time"]
        conn.close()
    except sqlite3.DatabaseError as e:
        log({"event": "db_error", "path": db_path, "error": str(e)})
    finally:
        try:
            os.remove(tmp)
        except Exception:
            pass

    return rows, max_ts


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────
def main():
    log({"event": "start", "message": f"Starting Browser Monitor. Logging to: {OUTPUT_LOG}"})

    state = load_state()
    users = get_logged_in_users()

    if not users:
        log({"event": "warning", "message": "No logged-in users detected."})
        save_state(state)
        return

    for username in users:
        for appdata in get_appdata_local(username):
            for browser, rel_path in BROWSERS.items():
                db_path = os.path.join(appdata, rel_path)
                if not os.path.exists(db_path):
                    continue

                state_key = f"{username}:{browser}"
                last_ts = state.get(state_key, 0)

                rows, new_ts = collect_history(db_path, last_ts)

                for row in rows:
                    log({
                        "event":       "browser_history",
                        "user":        username,
                        "browser":     browser,
                        "url":         row["url"],
                        "title":       row.get("title", ""),
                        "visit_time":  chrome_ts_to_iso(row["last_visit_time"]),
                        "visit_count": row["visit_count"],
                        "source":      "browser-monitor",
                    })

                if new_ts > last_ts:
                    state[state_key] = new_ts

    save_state(state)
    log({"event": "done", "message": "Collection complete."})


if __name__ == "__main__":
    main()
