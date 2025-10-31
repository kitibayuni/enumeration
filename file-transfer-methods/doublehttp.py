#!/usr/bin/env python3
# Simple two-way HTTP server: supports file upload + download
# Usage: python3 upload_server.py [port]
# Example: python3 upload_server.py 8080

import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
import cgi

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Serve directory listing or file download."""
        if self.path == '/':
            self.list_files()
        else:
            filepath = self.path.lstrip('/')
            if os.path.isfile(filepath):
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{os.path.basename(filepath)}"')
                self.end_headers()
                with open(filepath, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_error(404, "File not found")

    def list_files(self):
        """Display a simple HTML page with upload form + file list."""
        files = os.listdir('.')
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()

        self.wfile.write(b"<!DOCTYPE html><html><head><title>File Server</title></head>")
        self.wfile.write(b"<body><h2>Upload & Download Files</h2><hr>")
        self.wfile.write(b"<form method='POST' enctype='multipart/form-data'>"
                         b"<input name='file' type='file'/>"
                         b"<input type='submit' value='Upload'/></form><hr>")

        self.wfile.write(b"<h3>Files:</h3><ul>")
        for fname in files:
            if os.path.isfile(fname):
                f = fname.encode("utf-8")
                self.wfile.write(b"<li><a href='/" + f + b"'>" + f + b"</a></li>")
        self.wfile.write(b"</ul></body></html>")

    def do_POST(self):
        """Handle file upload."""
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD': 'POST',
                     'CONTENT_TYPE': self.headers['Content-Type'],})

        if 'file' in form:
            field_item = form['file']
            filename = os.path.basename(field_item.filename)
            if filename:
                with open(filename, 'wb') as output_file:
                    output_file.write(field_item.file.read())
                self.respond(f"✅ File '{filename}' uploaded successfully.")
            else:
                self.respond("❌ No file selected.")
        else:
            self.respond("❌ Invalid upload form.")

    def respond(self, message):
        """Helper to send an HTML response."""
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(f"<html><body><h2>{message}</h2><a href='/'>Back</a></body></html>".encode("utf-8"))

def run(server_class=HTTPServer, handler_class=SimpleHTTPRequestHandler, port=8000):
    print(f"Starting server on port {port}…")
    httpd = server_class(('0.0.0.0', port), handler_class)
    print(f"Serving HTTP on 0.0.0.0 port {port} (http://localhost:{port}/)")
    httpd.serve_forever()

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    run(port=port)
