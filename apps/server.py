import argparse
import socket
import struct

from common import REQUEST, add_transport_arguments, make_data
from protocol import Listener

localIP = "0.0.0.0"  # all interfaces


def serve(t):
  """Answer the request of one client: send back the number of bytes it asked for."""
  request = t.recv()
  (size,) = REQUEST.unpack(request)
  t.send(make_data(size))
  return size


def main():
  parser = argparse.ArgumentParser(description="Send back as many bytes as the client asks for.")
  add_transport_arguments(parser)
  args = parser.parse_args()

  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.bind((localIP, args.port))
  listener = Listener(s, args.protocol, args.window)
  print(f"Serving on UDP port {args.port} with protocol {args.protocol}, window {args.window}")

  # One client at a time
  while True:
    t = listener.accept()
    print(f"Request from {t.peer[0]}:{t.peer[1]}")
    try:
      size = serve(t)
      # The notebook reads this line to count retransmissions
      print(f"STATS {size} {t.stats['segments']} {t.stats['transmissions']}")
    except (ConnectionError, struct.error) as e:
      print(f"Transfer with {t.peer[0]}:{t.peer[1]} failed: {e}")
    finally:
      listener.done(t)


if __name__ == "__main__":
  main()
