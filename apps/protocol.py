"""A reliable transport protocol on top of UDP.

The client and the server exchange *messages* (byte strings of any length) through
a transport object `t`:

  t.send(data)     sends the message `data`, and returns once the peer has
                   acknowledged all of it
  data = t.recv()  returns the next message sent by the peer

UDP gives no guarantee: datagrams can be lost. To deliver a message reliably, the
transport splits it into numbered *segments* of at most MSS bytes. The receiver
acknowledges the segments it gets, and the sender retransmits the ones that are not
acknowledged in time.

The receiver side is the same for every protocol and is already implemented (see
Transport.handle). It buffers the segments that arrive out of order and reports
them in its ACKs (SACK). Your job is the sender side: the send_segments() method of
the protocol classes at the bottom of this file. StopAndWait is given as an example.

Format of a segment, in network byte order:

  | type (1 byte) | flags (1 byte) | number (4 bytes) | payload |

  DATA  number  = sequence number of the segment. Each direction of a connection
                  numbers its segments 0, 1, 2, ...
        flags   = LAST if the segment is the last one of a message
        payload = up to MSS bytes of the message
  ACK   number  = cumulative ACK: the sequence number of the next segment that the
                  receiver expects. All the segments before it have been received.
        payload = SACK blocks: up to MAX_SACK_BLOCKS pairs (start, end) of 4-byte
                  numbers, lowest first. The segments start, ..., end - 1 have been
                  received, out of order, beyond the cumulative ACK.

The receiver sends one ACK for every DATA segment it gets, duplicates included.
"""
import socket
import struct
import time
from collections import deque

# Segment types and flags
DATA = 0
ACK = 1
LAST = 0x01

HEADER = struct.Struct("!BBI")
SACK_BLOCK = struct.Struct("!II")

MSS = 1400              # bytes of payload per segment: fits in a 1500-byte Ethernet frame
TIMEOUT = 0.05          # s: retransmission timeout, a few times the RTT of the lab network
DEFAULT_WINDOW = 32     # segments: fixed window of sack, maximum window of window and sackwindow
INITIAL_WINDOW = 1      # segments: initial window of window and sackwindow
RCV_WINDOW = 1024       # segments: the receiver drops segments beyond rcv_next + RCV_WINDOW
MAX_SACK_BLOCKS = 16    # SACK blocks per ACK
GIVE_UP = 10            # s: give up if we hear nothing from the peer for this long
LINGER = 0.5            # s: see Transport.close(). Must be much larger than TIMEOUT.


class Segment:
  """A segment as transmitted in one UDP datagram."""

  def __init__(self, t, seq, payload=b"", flags=0, sack=()):
    self.t = t              # DATA or ACK
    self.seq = seq          # DATA: sequence number. ACK: cumulative ACK (see self.ack)
    self.payload = payload  # DATA only
    self.flags = flags      # DATA only
    self.sack = list(sack)  # ACK only: [(start, end), ...]

  @property
  def ack(self):
    """ACK only: the next sequence number expected by the receiver."""
    return self.seq

  def acknowledges(self, seq):
    """ACK only: True if this ACK says that segment `seq` has been received,
    either by the cumulative ACK or by a SACK block."""
    return seq < self.ack or any(start <= seq < end for start, end in self.sack)

  def encode(self):
    if self.t == ACK:
      body = b"".join(SACK_BLOCK.pack(start, end) for start, end in self.sack)
    else:
      body = self.payload
    return HEADER.pack(self.t, self.flags, self.seq) + body

  @staticmethod
  def decode(datagram):
    """The segment contained in `datagram`, or None if it is not a valid segment."""
    if len(datagram) < HEADER.size:
      return None
    t, flags, seq = HEADER.unpack_from(datagram)
    body = datagram[HEADER.size:]
    if t == DATA:
      return Segment(DATA, seq, body, flags)
    if t == ACK and len(body) % SACK_BLOCK.size == 0:
      return Segment(ACK, seq, sack=[block for block in SACK_BLOCK.iter_unpack(body)])
    return None

  def __repr__(self):
    if self.t == ACK:
      return f"ACK({self.ack}, sack={self.sack})"
    return f"DATA({self.seq}, {len(self.payload)} bytes{', LAST' if self.flags & LAST else ''})"


class Transport:
  """What every protocol has in common: everything but the sender's algorithm.

  A subclass only implements send_segments(). To do so, it uses:
    self.transmit(seg)         send a DATA segment (or send it again)
    self.wait_for_ack(deadline) wait for the next ACK, until a given time
    self.window                the window size given on the command line
    TIMEOUT, INITIAL_WINDOW    and the other constants above
  """

  def __init__(self, sock, peer, window=DEFAULT_WINDOW):
    self.sock = sock            # a UDP socket
    self.peer = peer            # (IP, port) of the other end
    self.window = window
    self.last_heard = time.monotonic()  # when we last received something from the peer
    self.stats = {"segments": 0, "transmissions": 0}

    # Sender side
    self.next_seq = 0           # sequence number of the next new segment

    # Receiver side
    self.rcv_next = 0           # next sequence number expected (the cumulative ACK)
    self.rcv_buffer = {}        # seq -> segment received out of order
    self.partial = []           # payloads of the message being reassembled
    self.messages = deque()     # complete messages, not yet returned by recv()

  # --- The interface used by the applications ---------------------------------

  def send(self, data):
    """Send the message `data`. Returns once the peer has acknowledged all of it."""
    segments = []
    for i in range(0, max(len(data), 1), MSS):  # an empty message is one empty segment
      segments.append(Segment(DATA, self.next_seq, data[i:i + MSS]))
      self.next_seq += 1
    segments[-1].flags = LAST
    self.stats["segments"] += len(segments)
    self.send_segments(segments)

  def recv(self):
    """Return the next message sent by the peer."""
    while not self.messages:
      if self._next_segment(self.last_heard + GIVE_UP) is None:
        received = sum(len(p) for p in self.partial)
        raise ConnectionError(f"nothing from the peer for {GIVE_UP} s"
                              f" ({received} bytes of the message received in order)")
    return self.messages.popleft()

  def close(self):
    """Keep acknowledging the peer's segments until it is silent for LINGER seconds.

    Our last ACK may have been lost: then the peer retransmits its last segment
    until it gets an ACK, and we must still be there to send it.
    """
    while self._next_segment(time.monotonic() + LINGER) is not None:
      pass

  # --- What a protocol must implement -----------------------------------------

  def send_segments(self, segments):
    """Deliver the DATA `segments` (a list, consecutive sequence numbers) to the peer.

    Returns once every segment has been acknowledged.
    """
    raise NotImplementedError(f"{type(self).__name__}.send_segments() is not implemented yet")

  # --- Tools for send_segments() ----------------------------------------------

  def transmit(self, seg):
    """Send the DATA segment `seg` to the peer (first transmission or retransmission)."""
    self.stats["transmissions"] += 1
    self._send(seg)

  def wait_for_ack(self, deadline):
    """Wait for the next ACK from the peer until `deadline`, a time.monotonic() value.

    Returns the ACK, or None if `deadline` passed before one arrived. The DATA
    segments that arrive meanwhile are handled automatically. Raises ConnectionError
    if the peer has been silent for GIVE_UP seconds.
    """
    while True:
      seg = self._next_segment(min(deadline, self.last_heard + GIVE_UP))
      if seg is None:
        if time.monotonic() - self.last_heard >= GIVE_UP:
          raise ConnectionError(f"nothing from the peer for {GIVE_UP} s")
        return None
      if seg.t == ACK:
        return seg

  # --- Internals: you do not need to read or change what follows -------------

  def _send(self, seg):
    try:
      self.sock.sendto(seg.encode(), self.peer)
    except OSError:
      pass  # e.g. the local queue is full: the same as a loss

  def _next_segment(self, deadline):
    """Receive the next segment from the peer and handle it. None at `deadline`."""
    while True:
      remaining = deadline - time.monotonic()
      if remaining <= 0:
        return None
      self.sock.settimeout(remaining)
      try:
        datagram, addr = self.sock.recvfrom(65535)
      except socket.timeout:
        return None
      except ConnectionRefusedError:
        continue
      seg = Segment.decode(datagram)
      if seg is not None and addr == self.peer:
        self.handle(seg)
        return seg

  def handle(self, seg):
    """The receiver side: buffer and acknowledge the DATA segments."""
    self.last_heard = time.monotonic()
    if seg.t != DATA:
      return
    if self.rcv_next <= seg.seq < self.rcv_next + RCV_WINDOW:
      self.rcv_buffer.setdefault(seg.seq, seg)
      # Deliver in order everything we can
      while self.rcv_next in self.rcv_buffer:
        s = self.rcv_buffer.pop(self.rcv_next)
        self.rcv_next += 1
        self.partial.append(s.payload)
        if s.flags & LAST:
          self.messages.append(b"".join(self.partial))
          self.partial = []
    # Always ACK, duplicates too: the previous ACK may have been lost
    self._send(Segment(ACK, self.rcv_next, sack=self._sack_blocks()))

  def _sack_blocks(self):
    blocks = []
    for seq in sorted(self.rcv_buffer):
      if blocks and blocks[-1][1] == seq:
        blocks[-1][1] = seq + 1
      elif len(blocks) == MAX_SACK_BLOCKS:
        break
      else:
        blocks.append([seq, seq + 1])
    return [tuple(b) for b in blocks]


class Listener:
  """Server side: waits for new clients on a UDP socket bound to a port."""

  RECENT = 30  # s: how long we remember the clients we have served

  def __init__(self, sock, protocol, window=DEFAULT_WINDOW):
    self.sock = sock
    self.protocol = protocol
    self.window = window
    self.finished = {}  # client address -> (its transport, when we finished with it)

  def accept(self):
    """Wait for the first segment of a new client, and return a transport connected to it."""
    self.sock.settimeout(None)
    while True:
      try:
        datagram, addr = self.sock.recvfrom(65535)
      except ConnectionRefusedError:
        continue
      seg = Segment.decode(datagram)
      if seg is None:
        continue
      if addr in self.finished:
        # A late segment from a client we have served: the old transport ACKs it again
        self.finished[addr][0].handle(seg)
      elif seg.t == DATA and seg.seq == 0:
        t = make_transport(self.protocol, self.sock, addr, self.window)
        t.handle(seg)
        return t

  def done(self, transport):
    """Call this when the server is done with a client."""
    now = time.monotonic()
    self.finished = {a: v for a, v in self.finished.items() if now - v[1] < self.RECENT}
    self.finished[transport.peer] = (transport, now)


# =============================================================================
# The protocols. A protocol is a subclass of Transport that implements
# send_segments(segments): deliver the DATA segments of one message, and return
# once all of them have been acknowledged.
#
# segments[i].seq == segments[0].seq + i. Use time.monotonic() for the timers.
# =============================================================================


class NoReliability(Transport):
  """Plain UDP: send each segment once, never retransmit.

  Fast, but if a single segment is lost the message is never delivered.
  """

  def send_segments(self, segments):
    for seg in segments:
      self.transmit(seg)


class StopAndWait(Transport):
  """Send one segment, wait for its ACK, then send the next one.

  If the ACK does not arrive within TIMEOUT seconds, the segment (or its ACK) was
  lost: retransmit the segment.
  """

  def send_segments(self, segments):
    for seg in segments:
      self.transmit(seg)
      deadline = time.monotonic() + TIMEOUT
      while True:
        ack = self.wait_for_ack(deadline)
        if ack is None:
          # Timeout: retransmit
          self.transmit(seg)
          deadline = time.monotonic() + TIMEOUT
        elif ack.acknowledges(seg.seq):
          break
        # Otherwise it is an old ACK (e.g. a duplicate): ignore it


class GrowingWindow(Transport):
  """Go-Back-N with a window that doubles after every successful round.

  The sender may have up to `wnd` segments in flight (sent but not acknowledged).
  It only uses the cumulative ACK and ignores the SACK blocks.

    1. Start with wnd = INITIAL_WINDOW and base = segments[0].seq, the oldest
       segment that is not acknowledged.
    2. Send every segment of [base, base + wnd) that has not been sent yet.
    3. An ACK with ack.ack > base acknowledges all the segments before ack.ack:
       move base to ack.ack, and restart the timer.
    4. When all the segments of the window (the "round") have been acknowledged
       without any timeout, double the window: wnd = min(2 * wnd, self.window).
    5. If no new ACK arrives within TIMEOUT seconds (the timer expires): go back N.
       Set wnd back to INITIAL_WINDOW and send again every segment from base on.
    6. Return when every segment is acknowledged.
  """

  def send_segments(self, segments):
    # TODO
    raise NotImplementedError("GrowingWindow is not implemented yet")


class SelectiveAck(Transport):
  """Selective repeat with SACK and a fixed window of self.window segments.

  The receiver buffers the segments that arrive out of order, and its ACKs say
  exactly which segments it has (ack.acknowledges(seq)). The sender only
  retransmits the segments that are missing.

    1. base is the oldest segment not acknowledged. Send every segment of
       [base, base + self.window) that has not been sent yet, and remember when you
       sent each one: every segment has its own timer.
    2. On an ACK, mark as acknowledged every segment it acknowledges: those before
       ack.ack and those in the SACK blocks. Move base past the acknowledged ones,
       which opens the window for new segments.
    3. When the timer of a segment that is not acknowledged expires (it was sent more
       than TIMEOUT seconds ago), retransmit that segment only, and restart its timer.
       Wait for ACKs until the earliest timer expires.
    4. Return when every segment is acknowledged.

  Optional: fast retransmit. If a segment is missing but the receiver has already
  SACKed 3 segments after it, it is probably lost: retransmit it right away instead
  of waiting for its timer (but only once per timer).
  """

  def send_segments(self, segments):
    # TODO
    raise NotImplementedError("SelectiveAck is not implemented yet")


class GrowingSack(Transport):
  """SelectiveAck, with the window of GrowingWindow.

  Segments are retransmitted selectively, as in SelectiveAck, but the window is not
  fixed: it starts at INITIAL_WINDOW, doubles every time a whole window of segments
  has been acknowledged without any timeout (up to self.window), and goes back to
  INITIAL_WINDOW when a timer expires.

  Hint: you can make this class a subclass of SelectiveAck, if you write SelectiveAck
  with a window variable and call methods (e.g. on_round_acked(), on_timeout()) where
  the window could change. Here you only override those methods.
  """

  def send_segments(self, segments):
    # TODO
    raise NotImplementedError("GrowingSack is not implemented yet")


# Command line name -> protocol
PROTOCOLS = {
  "udp": NoReliability,
  "stopwait": StopAndWait,
  "window": GrowingWindow,
  "sack": SelectiveAck,
  "sackwindow": GrowingSack,
}


def make_transport(protocol, sock, peer, window=DEFAULT_WINDOW):
  """A transport of the given protocol (a name in PROTOCOLS) to talk with `peer`."""
  return PROTOCOLS[protocol](sock, peer, window)
