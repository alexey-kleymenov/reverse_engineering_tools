from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sys
import datetime

DEFAULT_PAGE_FILENAME = 'index.html'
SERVER_PORT = 8080


class HTTPHoneypot(BaseHTTPRequestHandler):
    def __init__(self, *args):
        with open(DEFAULT_PAGE_FILENAME, 'rb') as fi:
            self.default_page = fi.read()
        super(HTTPHoneypot, self).__init__(*args)

    def log_message(self, msg_format, *args):
        return

    @staticmethod
    def publisher(data):
        print(json.dumps(data))
        sys.stdout.flush()

    def prepare_response_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def process_request(self, publisher, request_type):
        result = dict()
        result['request_type'] = request_type
        result['headers'] = self.headers.as_string()
        result['path'] = self.path
        result['client_ip'] = self.client_address[0]
        result['ts'] = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        if request_type == 'POST':
            content_len = int(self.headers.get('Content-Length'))
            post_body = self.rfile.read(content_len)
            result['post_body'] = post_body.decode('latin-1')
        publisher(result)

    # noinspection PyPep8Naming
    def do_HEAD(self):
        self.process_request(self.publisher, 'HEAD')
        self.prepare_response_headers()

    # noinspection PyPep8Naming
    def do_GET(self):
        self.process_request(self.publisher, 'GET')
        self.prepare_response_headers()
        self.wfile.write(self.default_page)

    # noinspection PyPep8Naming
    def do_POST(self):
        self.process_request(self.publisher, 'POST')
        self.prepare_response_headers()
        self.wfile.write(self.default_page)


def main():
    print('Starting the server at port %s' % SERVER_PORT)
    sys.stdout.flush()
    httpd = HTTPServer(('', SERVER_PORT), HTTPHoneypot)
    httpd.serve_forever()


if __name__ == '__main__':
    main()
