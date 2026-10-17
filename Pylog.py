import datetime
import json
import os
import platform
import subprocess
import threading
import time
import webbrowser
from collections import Counter
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"

MAX_TOP = 100

MONTH_MAP = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
    "May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
    "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
}
MONTH_NUMS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _sort_key_for_time(bucket: str) -> str:
    try:
        if "-W" in bucket:
            return bucket
        parts = bucket.split("/")
        if len(parts) == 3:
            day = parts[0]
            mon = MONTH_MAP.get(parts[1], parts[1])
            rest = parts[2]
            return f"{rest[:4]}-{mon}-{day:0>2}{rest[4:]}"
        elif len(parts) == 2:
            mon = MONTH_MAP.get(parts[0], parts[0])
            year = parts[1]
            return f"{year}-{mon}"
        return bucket
    except Exception:
        return bucket


KNOWN_ERROR_CODES = {
    400: ("Bad Request", "Check the request format and validate client input."),
    401: ("Unauthorized", "Check authentication credentials and login flow."),
    403: ("Forbidden", "Review permissions, access rules, and file ownership."),
    404: ("Not Found", "Fix the URL, route, link, or restore the missing resource."),
    405: ("Method Not Allowed", "Check that the endpoint accepts this HTTP method."),
    408: ("Request Timeout", "Check slow clients, proxy timeouts, and server load."),
    429: ("Too Many Requests", "Apply rate limiting and investigate repeated requests."),
    500: ("Internal Server Error", "Inspect application and server error logs for the exception."),
    502: ("Bad Gateway", "Check the upstream service, reverse proxy, and network connection."),
    503: ("Service Unavailable", "Check capacity, maintenance status, and dependent services."),
    504: ("Gateway Timeout", "Check slow upstream services and timeout settings."),
}


def explain_status(code: int) -> tuple[str, str]:
    if code in KNOWN_ERROR_CODES:
        return KNOWN_ERROR_CODES[code]
    if 400 <= code <= 499:
        return "Client Error", "Review the request, URL, authentication, and permissions."
    if 500 <= code <= 599:
        return "Server Error", "Inspect application logs, server health, and dependent services."
    return "Unrecognised Entry", "Check the log format and logging configuration."


def parse_line(raw_line: str) -> dict:
    line = raw_line.strip()
    if not line:
        raise ValueError("Empty line")

    first_token_end = line.find(" ")
    if first_token_end == -1:
        raise ValueError("Missing IP address")
    ip = line[:first_token_end]

    open_bracket = line.find("[")
    close_bracket = line.find("]")
    if open_bracket == -1 or close_bracket == -1 or close_bracket < open_bracket:
        raise ValueError("Missing or malformed timestamp")
    timestamp = line[open_bracket + 1:close_bracket]

    quote_start = line.find('"', close_bracket)
    if quote_start == -1:
        raise ValueError("Missing request section")
    quote_end = line.find('"', quote_start + 1)
    if quote_end == -1:
        raise ValueError("Unterminated request section")

    request_text = line[quote_start + 1:quote_end]
    request_parts = request_text.split()
    if len(request_parts) < 2:
        raise ValueError("Request section is incomplete")
    method, path = request_parts[0], request_parts[1]
    if not method.isalpha() or not method.isupper():
        raise ValueError("Invalid HTTP method")

    remainder = line[quote_end + 1:].strip().split()
    if not remainder:
        raise ValueError("Missing status code")
    if not remainder[0].isdigit() or len(remainder[0]) != 3:
        raise ValueError("Status code must be 3 digits")
    status = int(remainder[0])
    size = remainder[1] if len(remainder) > 1 else "-"

    day_str = timestamp[:2]
    mon_str = timestamp[3:6]
    year_str = timestamp[7:11]
    try:
        d = int(day_str)
        m = MONTH_NUMS.get(mon_str, 1)
        y = int(year_str)
        wk = datetime.date(y, m, d).isocalendar()[1]
        week_str = f"{y}-W{wk:02d}"
    except Exception:
        week_str = f"{year_str}-W01"

    return {
        "ip": ip,
        "timestamp": timestamp,
        "second": timestamp[:20],
        "minute": timestamp[:17],
        "hour": timestamp[:14],
        "day": timestamp[:11],
        "week": week_str,
        "month": f"{mon_str}/{year_str}",
        "method": method,
        "path": path,
        "status": status,
        "size": size,
        "raw": line,
    }


class LogAnalyzer:
    def __init__(self, top_limit: int = MAX_TOP, suspicious_ratio: float = 0.05, suspicious_min_hits: int = 100):
        self.top_limit = top_limit
        self.suspicious_ratio = suspicious_ratio
        self.suspicious_min_hits = suspicious_min_hits
        self.total_lines = 0
        self.malformed_lines = 0
        self.status_counter = Counter()
        self.ip_counter = Counter()
        self.path_counter = Counter()
        self.method_counter = Counter()
        self.error_log = []
        self.second_counter = Counter()
        self.minute_counter = Counter()
        self.hour_counter = Counter()
        self.day_counter = Counter()
        self.week_counter = Counter()
        self.month_counter = Counter()
        self.error_hour_counter = Counter()

    def _record_malformed(self, line_number: int, raw_line: str) -> None:
        self.malformed_lines += 1
        label, suggestion = explain_status(0)
        self.error_log.append({
            "lineNumber": line_number,
            "status": "Malformed",
            "description": label,
            "suggestion": suggestion,
            "raw": raw_line.strip(),
        })

    def _record_valid_line(self, line_number: int, entry: dict) -> None:
        self.status_counter[entry["status"]] += 1
        self.ip_counter[entry["ip"]] += 1
        self.path_counter[entry["path"]] += 1
        self.method_counter[entry["method"]] += 1
        self.second_counter[entry["second"]] += 1
        self.minute_counter[entry["minute"]] += 1
        self.hour_counter[entry["hour"]] += 1
        self.day_counter[entry["day"]] += 1
        self.week_counter[entry["week"]] += 1
        self.month_counter[entry["month"]] += 1

        if 400 <= entry["status"] <= 599:
            self.error_hour_counter[entry["hour"]] += 1
            label, suggestion = explain_status(entry["status"])
            self.error_log.append({
                "lineNumber": line_number,
                "status": entry["status"],
                "description": label,
                "suggestion": suggestion,
                "ip": entry["ip"],
                "path": entry["path"],
                "method": entry["method"],
                "timestamp": entry["timestamp"],
                "raw": entry["raw"],
            })

    def feed(self, log_text: str) -> None:
        for line_number, raw_line in enumerate(log_text.splitlines(), start=1):
            if not raw_line.strip():
                continue
            self.total_lines += 1
            try:
                entry = parse_line(raw_line)
            except ValueError:
                self._record_malformed(line_number, raw_line)
                continue
            self._record_valid_line(line_number, entry)

    def _top(self, counter: Counter) -> list[dict]:
        return [{"label": str(key), "count": count}
                for key, count in counter.most_common(self.top_limit)]

    def _find_suspicious_ips(self) -> list[dict]:
        threshold = max(self.suspicious_min_hits, self.total_lines * self.suspicious_ratio)
        return [{"ip": ip, "requests": count}
                for ip, count in self.ip_counter.most_common()
                if count >= threshold]

    def _find_error_spikes(self) -> list[dict]:
        if not self.hour_counter or not self.total_lines:
            return []
        total_errors = sum(c for code, c in self.status_counter.items() if 400 <= code <= 599)
        overall_rate = total_errors / self.total_lines
        spikes = []
        for hour, total in self.hour_counter.items():
            errors = self.error_hour_counter.get(hour, 0)
            if errors < 10:
                continue
            hour_rate = errors / total
            if overall_rate > 0 and hour_rate >= 2 * overall_rate:
                spikes.append({
                    "hour": hour,
                    "requests": total,
                    "errors": errors,
                    "errorRate": round(hour_rate * 100, 1),
                })
        return sorted(spikes, key=lambda x: x["errorRate"], reverse=True)

    def report(self, file_name: str = "server.log") -> dict:
        http_errors = sum(count for code, count in self.status_counter.items() if 400 <= code <= 599)
        total_bad = http_errors + self.malformed_lines
        error_rate = round((total_bad / self.total_lines) * 100, 2) if self.total_lines else 0.0

        return {
            "fileName": file_name,
            "summary": {
                "totalLines": self.total_lines,
                "malformedCount": self.malformed_lines,
                "httpErrors": http_errors,
                "errorRate": error_rate,
                "uniqueIps": len(self.ip_counter),
            },
            "topIps": self._top(self.ip_counter),
            "topPaths": self._top(self.path_counter),
            "topMethods": self._top(self.method_counter),
            "statusCodes": [{"label": str(code), "count": count}
                            for code, count in self.status_counter.most_common()],
            "errors": self.error_log,
            "suspiciousIps": self._find_suspicious_ips(),
            "requestsOverTime": {
                "second": sorted(
                    [{"label": k, "count": c} for k, c in self.second_counter.most_common(500)],
                    key=lambda x: _sort_key_for_time(x["label"]),
                ),
                "minute": sorted(
                    [{"label": k, "count": c} for k, c in self.minute_counter.items()],
                    key=lambda x: _sort_key_for_time(x["label"]),
                ),
                "hour": sorted(
                    [{"label": k, "count": c} for k, c in self.hour_counter.items()],
                    key=lambda x: _sort_key_for_time(x["label"]),
                ),
                "day": sorted(
                    [{"label": k, "count": c} for k, c in self.day_counter.items()],
                    key=lambda x: _sort_key_for_time(x["label"]),
                ),
                "week": sorted(
                    [{"label": k, "count": c} for k, c in self.week_counter.items()],
                    key=lambda x: x["label"],
                ),
                "month": sorted(
                    [{"label": k, "count": c} for k, c in self.month_counter.items()],
                    key=lambda x: _sort_key_for_time(x["label"]),
                ),
            },
            "errorSpikes": self._find_error_spikes(),
        }


def analyse_log(log_text: str, file_name: str = "server.log", top_limit: int = MAX_TOP) -> dict:
    analyzer = LogAnalyzer(top_limit=top_limit)
    analyzer.feed(log_text)
    return analyzer.report(file_name)


class RequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store, max-age=0")
        super().end_headers()

    def _send_json(self, status_code: int, payload: dict) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if urlparse(self.path).path != "/api/analyze":
            self.send_error(404, "Not found")
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(content_length).decode("utf-8"))
            log_text = payload.get("content")
            if not isinstance(log_text, str):
                raise ValueError("A text log file is required.")

            file_name = str(payload.get("fileName") or "server.log")
            result = analyse_log(log_text, file_name)
            self._send_json(200, result)
        except (json.JSONDecodeError, ValueError) as error:
            self._send_json(400, {"error": str(error)})


def open_browser(url: str) -> None:
    if platform.system() == "Linux":
        if "DISPLAY" not in os.environ and "WAYLAND_DISPLAY" not in os.environ:
            os.environ["DISPLAY"] = ":0"
    try:
        if not webbrowser.open(url):
            raise Exception("webbrowser returned False")
    except Exception:
        try:
            sys_name = platform.system()
            if sys_name == "Linux":
                subprocess.Popen(["xdg-open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif sys_name == "Darwin":
                subprocess.Popen(["open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif sys_name == "Windows":
                os.startfile(url)
        except Exception:
            pass

    if platform.system() == "Linux":
        time.sleep(0.4)
        for target in ["Pylog Analyzer", "Mozilla Firefox", "firefox", "Google Chrome", "chrome", "Chromium", "chromium"]:
            try:
                res = subprocess.run(["wmctrl", "-a", target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if res.returncode == 0:
                    break
            except Exception:
                break


def main():
    print("Log Analyzer running at http://127.0.0.1:8000")
    threading.Timer(0.5, lambda: open_browser("http://127.0.0.1:8000")).start()
    ThreadingHTTPServer(("0.0.0.0", 8000), RequestHandler).serve_forever()


if __name__ == "__main__":
    main()