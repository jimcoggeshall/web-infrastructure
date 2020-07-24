#!/opt/conda/bin/python

import socket
import socketserver
import datetime
import json
from json import JSONDecodeError

class MessageHandler(socketserver.BaseRequestHandler):

    def handle(self):
        streamer = iter(self._stream_packets(self._parse_message))
        while True:
            p = next(streamer)
            for m in p:
                self.request.sendall(
                    bytes(
                        json.dumps(m, separators=(":", ",")) + "\n", 
                        "utf-8"
                    )
                )

    def _stream_packets(self, _parse):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(("0.0.0.0", 22055))
            while True:
                p, _ = s.recvfrom(65536)
                parsed = ""
                while parsed == "":
                    try:
                        parsed = _parse(p)
                    except JSONDecodeError:
                        parsed = ""
                        pn, _ = s.recvfrom(65536)
                        p += pn
                yield parsed

    def _parse_message(self, x):
        s = x.decode("utf-8").rstrip()
        return [json.loads(m) for m in s.split("\n")]

def main():
    with socketserver.TCPServer(("127.0.0.1", 11111), MessageHandler) as server:
        server.serve_forever()

if __name__ == "__main__":
    main()
