"""
Test Target - Deliberately vulnerable application for scanner validation

This application contains INTENTIONAL security vulnerabilities for testing.
DO NOT deploy this application in production.
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import urllib.parse

# Intentionally vulnerable test data
USERS = {
    "1": {"id": "1", "username": "admin", "email": "admin@test.local", "role": "admin", "password": "admin123"},
    "2": {"id": "2", "username": "user1", "email": "user1@test.local", "role": "user", "password": "user123"},
    "3": {"id": "3", "username": "user2", "email": "user2@test.local", "role": "user", "password": "pass456"},
}

# VULNERABILITY: Hardcoded API key
API_KEY = "sk-test-FAKE-KEY-DO-NOT-USE-1234567890abcdef"
# VULNERABILITY: Hardcoded database password
DB_PASSWORD = "super_secret_db_password_123"


class VulnerableHandler(BaseHTTPRequestHandler):
    """Intentionally vulnerable HTTP handler for testing security scanners."""

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        # VULNERABILITY: No security headers
        # VULNERABILITY: Wildcard CORS
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Server", "VulnerableTestServer/1.0")

        if path == "/":
            self.end_headers()
            self.wfile.write(self._index_page().encode())

        elif path == "/api/users":
            # VULNERABILITY: IDOR - No authorization check
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            # Exposes all user data including passwords
            self.wfile.write(json.dumps(list(USERS.values())).encode())

        elif path.startswith("/api/user/"):
            # VULNERABILITY: IDOR - Direct object reference without auth
            user_id = path.split("/")[-1]
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            if user_id in USERS:
                self.wfile.write(json.dumps(USERS[user_id]).encode())
            else:
                self.wfile.write(json.dumps({"error": "User not found"}).encode())

        elif path == "/api/search":
            # VULNERABILITY: Reflected XSS
            query = params.get("q", [""])[0]
            self.end_headers()
            # Reflecting user input without encoding
            self.wfile.write(f"""<html>
<body>
<h1>Search Results</h1>
<p>You searched for: {query}</p>
<p>No results found.</p>
</body>
</html>""".encode())

        elif path == "/api/debug":
            # VULNERABILITY: Information disclosure
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "debug": True,
                "api_key": API_KEY,
                "db_password": DB_PASSWORD,
                "environment": "development",
                "python_path": "/usr/local/bin/python3",
                "server_ip": "192.168.1.100",
            }).encode())

        elif path == "/api/error":
            # VULNERABILITY: Stack trace in error response
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"""Traceback (most recent call last):
  File "/app/server.py", line 42, in handle_request
    result = database.query(user_input)
  File "/app/database.py", line 15, in query
    cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")
TypeError: unsupported operand type(s) for +: 'NoneType' and 'str'""")

        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def do_OPTIONS(self):
        # VULNERABILITY: Overly permissive CORS preflight
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", "*"))
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, TRACE")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/login":
            # VULNERABILITY: No rate limiting, exposes whether username exists
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                data = {}

            username = data.get("username", "")
            password = data.get("password", "")

            for user in USERS.values():
                if user["username"] == username:
                    if user["password"] == password:
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        # VULNERABILITY: Token in response without httpOnly cookie
                        self.send_header("Access-Control-Allow-Origin", "*")
                        self.end_headers()
                        self.wfile.write(json.dumps({
                            "token": "eyJhbGciOiJIUzI1NiJ9.FAKE-TEST-TOKEN.signature",
                            "user": user,
                        }).encode())
                        return
                    else:
                        self.send_response(401)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps({"error": "Invalid password"}).encode())
                        return

            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            # VULNERABILITY: Different error for nonexistent user (user enumeration)
            self.wfile.write(json.dumps({"error": "User not found"}).encode())
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def _index_page(self):
        return """<!DOCTYPE html>
<html>
<head>
    <title>Test Target - Deliberately Vulnerable</title>
    <style>
        body { font-family: Arial, sans-serif; background: #1a1a2e; color: #e0e0e0; padding: 2rem; }
        h1 { color: #e94560; }
        a { color: #0f3460; }
        .warning { background: #e94560; color: white; padding: 1rem; border-radius: 8px; margin: 1rem 0; }
        .endpoint { background: #16213e; padding: 0.5rem 1rem; margin: 0.25rem 0; border-radius: 4px; font-family: monospace; }
    </style>
    <script>
        // VULNERABILITY: Sensitive data in localStorage
        localStorage.setItem('token', 'test-auth-token-12345');
        localStorage.setItem('auth', 'bearer-fake-token');

        // VULNERABILITY: eval usage
        function processData(data) {
            eval('var result = ' + data);
            return result;
        }

        // VULNERABILITY: innerHTML with user input
        function showResult(input) {
            document.getElementById('result').innerHTML = input;
        }

        // VULNERABILITY: Client-side authorization
        function checkAdmin() {
            var role = localStorage.getItem('role');
            if (role === 'admin') {
                document.getElementById('admin-panel').style.display = 'block';
            }
        }
    </script>
</head>
<body>
    <div class="warning">⚠️ This is a DELIBERATELY VULNERABLE test application. DO NOT deploy in production.</div>
    <h1>Test Target Application</h1>
    <h2>Available Endpoints:</h2>
    <div class="endpoint">GET /api/users - List all users (IDOR)</div>
    <div class="endpoint">GET /api/user/:id - Get user by ID (IDOR)</div>
    <div class="endpoint">GET /api/search?q=... - Search (Reflected XSS)</div>
    <div class="endpoint">POST /api/login - Login (User enumeration)</div>
    <div class="endpoint">GET /api/debug - Debug info (Information disclosure)</div>
    <div class="endpoint">GET /api/error - Error page (Stack trace disclosure)</div>
    <div id="result"></div>
    <div id="admin-panel" style="display:none">Admin Panel</div>
</body>
</html>"""

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass


def run_test_target(host="127.0.0.1", port=5173):
    """Run the test target server."""
    server = HTTPServer((host, port), VulnerableHandler)
    print(f"🎯 Test target running at http://{host}:{port}")
    print("⚠️  This is a deliberately vulnerable application for testing only!")
    print("Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping test target...")
        server.server_close()


if __name__ == "__main__":
    run_test_target()
