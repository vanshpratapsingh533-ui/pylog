import json
import threading
import webbrowser
from collections import Counter
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"
HOW_MANY_TOP_ENTRIES = 5


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

    # IP address
    first_token_end = line.find(" ")
    if first_token_end == -1:
        raise ValueError("Missing IP address")
    ip = line[:first_token_end]

    # Timestamp
    open_bracket = line.find("[")
    close_bracket = line.find("]")
    if open_bracket == -1 or close_bracket == -1 or close_bracket < open_bracket:
        raise ValueError("Missing or malformed timestamp")
    timestamp = line[open_bracket + 1:close_bracket]

    # Request line
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

    # Status code and size
    remainder = line[quote_end + 1:].strip().split()
    if not remainder:
        raise ValueError("Missing status code")
    if not remainder[0].isdigit() or len(remainder[0]) != 3:
        raise ValueError("Status code must be 3 digits")
    status = int(remainder[0])
    size = remainder[1] if len(remainder) > 1 else "-"
    return {
        "ip": ip,
        "timestamp": timestamp,
        "method": method,
        "path": path,
        "status": status,
        "size": size,
        "raw": line,
    }

class LogAnalyzer:
    def __init__(self, suspicious_ratio: float = 0.15, suspicious_min_hits: int = 20):
        self.suspicious_ratio = suspicious_ratio
        self.suspicious_min_hits = suspicious_min_hits
        self.total_lines = 0
        self.malformed_lines = 0
        self.status_counter = Counter()
        self.ip_counter = Counter()
        self.path_counter = Counter()
        self.method_counter = Counter()
        self.error_log = []

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

        if 400 <= entry["status"] <= 599:
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
        """Process every non-blank line in the given log text."""
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
                for key, count in counter.most_common(HOW_MANY_TOP_ENTRIES)]

    def _find_suspicious_ips(self) -> list[dict]:
        threshold = max(self.suspicious_min_hits, self.total_lines * self.suspicious_ratio)
        return [{"ip": ip, "requests": count}
                for ip, count in self.ip_counter.most_common()
                if count >= threshold]

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
        }

def analyse_log(log_text: str, file_name: str = "server.log") -> dict:
    analyzer = LogAnalyzer()
    analyzer.feed(log_text)
    return analyzer.report(file_name)

class RequestHandler(SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def _send_json(self, status_code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
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

def main():
    print("Log Analyzer running at http://localhost:8000")
    threading.Timer(1.0, lambda: webbrowser.open_new_tab("http://localhost:8000")).start()
    ThreadingHTTPServer(("127.0.0.1", 8000), RequestHandler).serve_forever()

if __name__ == "__main__":
    main()