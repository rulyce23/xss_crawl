from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        p = urlparse(self.path)
        qs = parse_qs(p.query)
        # echo the first parameter value if present
        val = ''
        if qs:
            first = next(iter(qs.values()))
            if first:
                val = first[0]
        # include CVE and CVSS in the response body to test extraction
        body = f"""
        <html>
        <head><title>Test</title></head>
        <body>
        <h1>Test Page</h1>
        <p>Reflected: {val}</p>
        <p>CVE-2025-12345</p>
        <p>Base Score: 9.8</p>
        </body>
        </html>
        """
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body.encode('utf-8'))))
        self.end_headers()
        self.wfile.write(body.encode('utf-8'))

if __name__ == '__main__':
    server = HTTPServer(('127.0.0.1', 8000), Handler)
    print('Starting test server on http://127.0.0.1:8000')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
    print('Server stopped')
