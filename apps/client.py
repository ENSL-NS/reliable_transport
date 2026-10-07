import argparse
import socket
import sys
import time

from common import REQUEST, add_transport_arguments, make_data
from protocol import make_transport


def main():
  parser = argparse.ArgumentParser(description="Ask the server for SIZE bytes and time the transfer.")
  parser.add_argument("server", metavar="SERVER_IP")
  parser.add_argument("size", metavar="SIZE", type=int, help="number of bytes to ask for")
  add_transport_arguments(parser)
  args = parser.parse_args()

  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  server = (socket.gethostbyname(args.server), args.port)
  t = make_transport(args.protocol, s, server, args.window)

  start = time.perf_counter()
  try:
    t.send(REQUEST.pack(args.size))
    data = t.recv()
  except ConnectionError as e:
    sys.exit(f"error: {e}")
  end = time.perf_counter()
  t.close()  # not timed: only answers the server's last retransmissions, if any

  status = "OK" if data == make_data(args.size) else "CORRUPTED"
  # Do not change this line: the notebook reads it to collect your measurements.
  # The time includes the request and the whole transfer.
  print(f"RESULT {len(data)} {end - start:.6f} {status}")


if __name__ == "__main__":
  main()
