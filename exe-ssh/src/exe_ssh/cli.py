#!/usr/bin/env python3
"""An SSH-ish interactive terminal for an exe.dev VM, over HTTPS (no port 22).

Usage:
    exe-ssh <vm> [session-name]   attach (session-name defaults to a random
                                   color name)
    exe-ssh <vm> --list           list existing sessions
    exe-clone <vm> [--rm]           clone <vm>, attach to the clone, and offer
                                   to remove it when you exit its shell

The session is persistent and the client auto-reconnects, so dropping the
network (or closing your laptop) reattaches you to the same shell. A dropped
link is detected within a few seconds via WebSocket keepalive pings.

With no session-name, a new random color-name session is created; pass an
explicit name to reattach to an existing one, or use --list to see what's
running.

Like ssh(1), a few escape sequences are recognized right after Enter:
  ~.   terminate the connection
  ~^Z  suspend exe-ssh (resume with 'fg')
  ~~   send a literal '~'
  ~?   list these sequences
"""

# Standard library only!
import argparse
import base64
import errno
import hashlib
import json
import os
import random
import re
import select
import signal
import socket
import ssl
import struct
import subprocess
import sys
import termios
import time
import tty
from urllib.parse import urlencode

TOKEN_TTL_SECONDS = 300

# Liveness probing. A silently-dropped link (laptop sleep, Wi-Fi roam, NAT
# idle-timeout) sends no TCP FIN/RST, so select() never wakes and an idle
# shell's writes don't fail for minutes. We instead send our own WebSocket
# pings and treat a too-long silence as a dead link, so reconnect is fast.
PING_INTERVAL = 4.0   # send a ping this often when otherwise idle
DEAD_AFTER = 12.0     # no bytes at all for this long => assume the link died
CONNECT_TIMEOUT = 10  # TCP connect + WebSocket handshake budget

# Session names are drawn from this palette of color names; a new session gets
# a random one.
SESSION_COLORS = [
    "amber", "aqua", "azure", "beige", "bisque", "black", "blue", "bronze", "brown", "coral",
    "cream", "crimson", "cyan", "denim", "ebony", "emerald", "fuchsia", "gold", "gray", "green",
    "indigo", "ivory", "jade", "khaki", "lavender", "lemon", "lilac", "lime", "linen", "magenta",
    "maroon", "mauve", "mint", "navy", "ochre", "olive", "orange", "orchid", "peach", "pearl",
    "periwinkle", "pink", "plum", "purple", "red", "rose", "ruby", "rust", "saffron", "sage",
    "salmon", "sand", "sapphire", "scarlet", "sepia", "silver", "slate", "snow", "tan", "teal",
    "thistle", "tomato", "turquoise", "umber", "vanilla", "violet", "wheat", "white", "wine", "yellow",
    "amethyst", "apricot", "ash", "auburn", "buff", "cardinal", "carmine", "cerise", "charcoal", "cherry",
    "chestnut", "chocolate", "cinnamon", "claret", "cobalt", "copper", "cornflower", "eggplant", "flax", "garnet",
    "ginger", "goldenrod", "gunmetal", "hazel", "honeydew", "ice", "iron", "jasmine", "jet", "mango",
]


def random_session_name(avoid=()):
    """Pick a random color-name session, preferring names not already in
    `avoid` so a fresh session doesn't collide with an existing one; only if
    every color is taken do we fall back to any color."""
    avoid = set(avoid)
    available = [n for n in SESSION_COLORS if n not in avoid]
    return random.choice(available or SESSION_COLORS)


# ANSI colors for status banners. Suppressed when stderr isn't a tty (e.g.
# piped or captured), so logs stay plain there.
RED = "\x1b[31m"
GREEN = "\x1b[32m"
YELLOW = "\x1b[33m"
_RESET = "\x1b[0m"


# Whether the last line written to stderr was a banner, so the next banner
# can overwrite it instead of stacking status lines.
_banner_shown = False


def log(msg):
    global _banner_shown
    _banner_shown = False
    sys.stderr.write("\r\x1b[2K" + msg + "\r\n")
    sys.stderr.flush()


def banner(msg, color="", replace=False):
    """A status line that stands out from shell output: bold, reverse-video,
    and color when stderr is a terminal. Used for reconnection state so the
    user can plainly see the link dropped and came back. With replace, it
    overwrites the previous line if that was also a banner."""
    global _banner_shown
    tty = sys.stderr.isatty()
    if color and tty:
        msg = f"{color}\x1b[1m\x1b[7m exe-ssh: {msg} {_RESET}"
    else:
        msg = f"exe-ssh: {msg}"
    if replace and _banner_shown and tty:
        sys.stderr.write("\x1b[1A")  # cursor up onto the previous banner
    log(msg)
    _banner_shown = True


def b64url(data: bytes) -> str:
    """base64url without padding (RFC 4648 section 5)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def find_key(explicit, host):
    """Resolve the SSH private key to sign with.

    With no -i/--key, ask ssh(1) itself which identity it would use for the
    box host (`ssh -G`), honoring the user's ssh_config, and pick the first
    candidate that exists on disk.
    """
    if explicit:
        path = os.path.expanduser(explicit)
        if not os.path.exists(path):
            sys.exit(f"error: ssh key not found: {path}")
        return path
    try:
        out = subprocess.check_output(["ssh", "-G", host], text=True)
    except FileNotFoundError:
        sys.exit("error: ssh not found on PATH")
    except subprocess.CalledProcessError as e:
        sys.exit(f"error: ssh -G {host} failed: {e}")
    for line in out.splitlines():
        if line.lower().startswith("identityfile "):
            path = os.path.expanduser(line.split(None, 1)[1].strip())
            if os.path.exists(path):
                return path
    sys.exit("error: no SSH key found; pass -i/--key, or create and register one "
             "(ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519, then ssh exe.dev ssh-key add)")


def generate_token(key_path, namespace, cmds=None):
    """Mint a short-lived exe0 API token by SSH-signing a permissions blob.

    cmds restricts which exe.dev commands the token may run (for the
    POST /exec API). See https://exe.dev/docs/https-api-local-key.
    """
    perms = {"exp": int(time.time()) + TOKEN_TTL_SECONDS}
    if cmds is not None:
        perms["cmds"] = list(cmds)
    payload = json.dumps(perms, separators=(",", ":")).encode("utf-8")

    try:
        armored = subprocess.check_output(
            ["ssh-keygen", "-Y", "sign", "-f", key_path, "-n", namespace],
            input=payload, stderr=subprocess.PIPE,
        ).decode("ascii")
    except FileNotFoundError:
        sys.exit("error: ssh-keygen not found on PATH")
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode(errors="replace").strip()
        raise SignError(f"ssh-keygen sign failed: {stderr}", stderr)

    # Strip the PEM armor (-----BEGIN/END SSH SIGNATURE-----) and decode.
    lines = [ln for ln in armored.splitlines() if ln and not ln.startswith("-----")]
    sig_der = base64.b64decode("".join(lines))

    return "exe0." + b64url(payload) + "." + b64url(sig_der)


class WSError(Exception):
    pass


class SignError(Exception):
    def __init__(self, msg, stderr=""):
        super().__init__(msg)
        # ssh-keygen's last stderr line is the most specific one, e.g.
        # "Signing (stdin) failed: agent refused operation".
        lines = stderr.splitlines()
        self.reason = lines[-1].strip() if lines else ""


class WebSocket:
    """Minimal RFC 6455 WebSocket client (text frames only, with masking)."""

    OP_CONT = 0x0
    OP_TEXT = 0x1
    OP_BINARY = 0x2
    OP_CLOSE = 0x8
    OP_PING = 0x9
    OP_PONG = 0xA

    # Application-private close code (RFC 6455 4000-4999) the exe.dev terminal
    # server sends when the remote shell itself exits (Ctrl-D / logout), as
    # opposed to a generic close (server shutdown, error) we should retry.
    CLOSE_SHELL_EXITED = 4001

    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def __init__(self, sock):
        self.sock = sock
        self._buf = b""
        # State for reassembling fragmented (continuation) messages.
        self._frag_opcode = None
        self._frag_payload = bytearray()

    @classmethod
    def connect(cls, host, port, path, headers, insecure, plaintext=False,
                connect_host=None, timeout=CONNECT_TIMEOUT):
        # connect_host lets us TCP-connect somewhere (e.g. localhost) while
        # still presenting `host` in the Host header / SNI / Authorization.
        raw = socket.create_connection((connect_host or host, port), timeout=timeout)
        # Belt-and-suspenders: ask the kernel to probe dead peers too. Our own
        # application-level pings are the primary signal, but TCP keepalive
        # also tears down a half-open socket the OS can detect.
        try:
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            for opt, val in (("TCP_KEEPIDLE", 5), ("TCP_KEEPINTVL", 3),
                             ("TCP_KEEPCNT", 3)):
                if hasattr(socket, opt):
                    raw.setsockopt(socket.IPPROTO_TCP, getattr(socket, opt), val)
        except OSError:
            pass
        if plaintext:
            sock = raw
        else:
            ctx = ssl.create_default_context()
            if insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=host)

        key = base64.b64encode(os.urandom(16)).decode("ascii")
        req = [
            f"GET {path} HTTP/1.1",
            f"Host: {host}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
        ]
        for k, v in headers.items():
            req.append(f"{k}: {v}")
        req.append("\r\n")
        sock.sendall("\r\n".join(req).encode("ascii"))

        ws = cls(sock)
        status_line, resp_headers = ws._read_handshake()
        parts = status_line.split(" ", 2)
        if len(parts) < 2 or parts[1] != "101":
            sock.close()
            raise WSError(f"handshake failed: {status_line}")

        # Verify Sec-WebSocket-Accept (RFC 6455 4.1) so we don't speak the
        # WebSocket framing protocol to a server that didn't actually agree.
        expect = base64.b64encode(
            hashlib.sha1((key + cls.GUID).encode("ascii")).digest()
        ).decode("ascii")
        got = None
        for h in resp_headers:
            name, _, val = h.partition(":")
            if name.strip().lower() == "sec-websocket-accept":
                got = val.strip()
        if got != expect:
            sock.close()
            raise WSError("handshake failed: bad Sec-WebSocket-Accept")

        ws.sock.setblocking(False)
        return ws

    def _read_handshake(self):
        # Read until end of HTTP headers (CRLFCRLF).
        while b"\r\n\r\n" not in self._buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise WSError("connection closed during handshake")
            self._buf += chunk
        head, self._buf = self._buf.split(b"\r\n\r\n", 1)
        lines = head.decode("latin-1").split("\r\n")
        return lines[0], lines[1:]

    def fileno(self):
        return self.sock.fileno()

    def send_text(self, data: str):
        self._send_frame(self.OP_TEXT, data.encode("utf-8"))

    def _send_frame(self, opcode, payload: bytes):
        b1 = 0x80 | opcode  # FIN + opcode
        header = bytearray([b1])
        n = len(payload)
        mask_bit = 0x80  # client frames must be masked
        if n < 126:
            header.append(mask_bit | n)
        elif n < 65536:
            header.append(mask_bit | 126)
            header += struct.pack("!H", n)
        else:
            header.append(mask_bit | 127)
            header += struct.pack("!Q", n)
        mask = os.urandom(4)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self._send_all(bytes(header) + masked)

    def _send_all(self, data):
        # Socket is non-blocking; loop until everything is flushed.
        view = memoryview(data)
        while view:
            try:
                sent = self.sock.send(view)
                if sent == 0:
                    raise WSError("connection closed while sending")
                view = view[sent:]
            except ssl.SSLWantWriteError:
                select.select([], [self.sock], [], 1)
            except (ssl.SSLWantReadError,):
                select.select([self.sock], [], [], 1)
            except BlockingIOError:
                select.select([], [self.sock], [], 1)

    def recv_into_buffer(self):
        """Pull available bytes off the socket. Returns False on EOF.

        For TLS sockets a single TCP read can decrypt into more buffered
        application data than one recv() returns; select() on the raw fd
        wouldn't fire again, so drain ssl pending() until it's empty.
        """
        try:
            chunk = self.sock.recv(65536)
        except ssl.SSLWantReadError:
            return True
        except BlockingIOError:
            return True
        if not chunk:
            return False
        self._buf += chunk
        pending = getattr(self.sock, "pending", None)
        if pending is not None:
            while pending() > 0:
                try:
                    more = self.sock.recv(65536)
                except (ssl.SSLWantReadError, BlockingIOError):
                    break
                if not more:
                    break
                self._buf += more
        return True

    def frames(self):
        """Yield (opcode, payload) for each complete *message*.

        Reassembles RFC 6455 fragmented messages (FIN=0 + continuation
        frames) so callers always see whole text/binary messages. Control
        frames (ping/pong/close) are never fragmented and pass through.
        """
        while True:
            parsed = self._parse_one()
            if parsed is None:
                return
            fin, opcode, payload = parsed
            if opcode in (self.OP_PING, self.OP_PONG, self.OP_CLOSE):
                yield opcode, payload
                continue
            if opcode == self.OP_CONT:
                if self._frag_opcode is None:
                    raise WSError("unexpected continuation frame")
                self._frag_payload += payload
                if fin:
                    op, data = self._frag_opcode, bytes(self._frag_payload)
                    self._frag_opcode = None
                    self._frag_payload = bytearray()
                    yield op, data
                continue
            # New data frame (TEXT/BINARY).
            if fin:
                yield opcode, payload
            else:
                self._frag_opcode = opcode
                self._frag_payload = bytearray(payload)

    def _parse_one(self):
        buf = self._buf
        if len(buf) < 2:
            return None
        b0, b1 = buf[0], buf[1]
        fin = bool(b0 & 0x80)
        opcode = b0 & 0x0F
        masked = b1 & 0x80
        length = b1 & 0x7F
        idx = 2
        if length == 126:
            if len(buf) < idx + 2:
                return None
            (length,) = struct.unpack("!H", buf[idx:idx + 2])
            idx += 2
        elif length == 127:
            if len(buf) < idx + 8:
                return None
            (length,) = struct.unpack("!Q", buf[idx:idx + 8])
            idx += 8
        mask = b""
        if masked:
            if len(buf) < idx + 4:
                return None
            mask = buf[idx:idx + 4]
            idx += 4
        if len(buf) < idx + length:
            return None
        payload = bytearray(buf[idx:idx + length])
        if masked:
            for i in range(length):
                payload[i] ^= mask[i % 4]
        self._buf = buf[idx + length:]
        return fin, opcode, bytes(payload)

    def ping(self, payload=b""):
        self._send_frame(self.OP_PING, payload)

    def pong(self, payload):
        self._send_frame(self.OP_PONG, payload)

    def close(self):
        try:
            self._send_frame(self.OP_CLOSE, b"")
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


def http_get_json(host, port, path, headers, insecure, plaintext=False,
                  connect_host=None, timeout=CONNECT_TIMEOUT):
    """Blocking HTTP GET that returns parsed JSON; non-200 raises WSError."""
    code, body = http_request("GET", host, port, path, headers, insecure,
                              plaintext=plaintext, connect_host=connect_host,
                              timeout=timeout)
    if code != 200:
        raise WSError(f"HTTP {code}: {body.decode('utf-8', 'replace').strip()}")
    return json.loads(body.decode("utf-8"))


def http_request(method, host, port, path, headers, insecure, body=None,
                 plaintext=False, connect_host=None, timeout=CONNECT_TIMEOUT):
    """Minimal blocking HTTP/1.1 request; returns (status code, body bytes).

    Shares the WebSocket client's connection conventions (connect_host/SNI/
    plaintext). Used for the sessions-list endpoint and the exe.dev /exec
    API, which are plain requests rather than WebSocket upgrades.

    Deliberately tiny: handles Content-Length or Connection: close framing,
    with hard caps on header/body size. It does NOT implement chunked transfer
    encoding -- we send Connection: close so a well-behaved HTTP/1.1 server
    delimits by EOF instead; if a response is chunked anyway we fail loudly
    rather than mis-parse.
    """
    # We interpolate host/path into the raw request line, so reject anything
    # that could smuggle extra headers. (Callers already validate these, but
    # this is the security-sensitive choke point.)
    for label, val in (("host", host), ("path", path)):
        if "\r" in val or "\n" in val:
            raise WSError(f"refusing to send {label} with embedded newline")
    max_header = 64 * 1024
    max_body = 4 * 1024 * 1024

    raw = socket.create_connection((connect_host or host, port), timeout=timeout)
    try:
        if plaintext:
            sock = raw
        else:
            ctx = ssl.create_default_context()
            if insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=host)
    except Exception:
        raw.close()
        raise
    try:
        req = [f"{method} {path} HTTP/1.1", f"Host: {host}", "Connection: close",
               "Accept: application/json"]
        if body is not None:
            req.append(f"Content-Length: {len(body)}")
        for k, v in headers.items():
            req.append(f"{k}: {v}")
        req.append("\r\n")
        sock.sendall("\r\n".join(req).encode("ascii") + (body or b""))

        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                raise WSError("connection closed during response headers")
            buf += chunk
            if len(buf) > max_header:
                raise WSError("response headers too large")
        head, resp = buf.split(b"\r\n\r\n", 1)
        lines = head.decode("latin-1").split("\r\n")
        status = lines[0].split(" ", 2)
        if len(status) < 2 or not status[1].isdigit():
            raise WSError(f"malformed status line: {lines[0]!r}")
        code = int(status[1])

        length = None
        for h in lines[1:]:
            n, _, v = h.partition(":")
            n = n.strip().lower()
            if n == "transfer-encoding" and "chunked" in v.lower():
                raise WSError("chunked transfer encoding not supported")
            if n == "content-length":
                try:
                    length = int(v.strip())
                except ValueError:
                    length = None

        # Honor Content-Length when present; otherwise read to EOF (we asked
        # for Connection: close, so the server closes when done).
        while length is None or len(resp) < length:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
            if len(resp) > max_body:
                raise WSError("response body too large")
        if length is not None:
            resp = resp[:length]
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return code, resp


# ---------------------------------------------------------------------------
# Terminal session
# ---------------------------------------------------------------------------


def term_size(fd):
    try:
        cols, rows = os.get_terminal_size(fd)
        return rows, cols
    except OSError:
        return 24, 80


# The escape character, like ssh(1), is only recognized right after a newline
# (start of line). "~?" lists the supported sequences.
ESCAPE_CHAR = ord("~")
ESCAPE_HELP = (
    "\r\nSupported escape sequences (recognized after Enter):\r\n"
    "  ~.   terminate the connection\r\n"
    "  ~^Z  suspend exe-ssh\r\n"
    "  ~~   send a literal '~'\r\n"
    "  ~?   this message\r\n"
)


class EscapeFilter:
    """Recognize ssh-style ``~`` escape sequences in the local input stream.

    Fed raw bytes from the tty, it returns the bytes that should actually be
    forwarded to the remote shell and, separately, a list of local actions
    ("quit", "suspend", "help") triggered by escape sequences. As in ssh(1),
    the escape char is only special at the start of a line.
    """

    def __init__(self):
        # Start-of-connection counts as start-of-line, matching ssh.
        self.at_line_start = True
        self.after_escape = False

    def feed(self, data: bytes):
        out = bytearray()
        actions = []
        for byte in data:
            if self.after_escape:
                self.after_escape = False
                if byte == ESCAPE_CHAR:
                    out.append(ESCAPE_CHAR)        # ~~ -> literal ~
                elif byte == ord("."):
                    actions.append("quit")
                elif byte == 0x1A:                 # ~^Z -> suspend
                    actions.append("suspend")
                elif byte == ord("?"):
                    actions.append("help")
                else:
                    # Not a recognized command: pass the ~ and this byte through.
                    out.append(ESCAPE_CHAR)
                    out.append(byte)
                self.at_line_start = byte in (0x0D, 0x0A)
                continue
            if self.at_line_start and byte == ESCAPE_CHAR:
                # Hold the ~ until we see the next byte to decide.
                self.after_escape = True
                self.at_line_start = False
                continue
            out.append(byte)
            self.at_line_start = byte in (0x0D, 0x0A)
        return bytes(out), actions


def run_session(ws, stdin_fd, old_termios):
    """Pump bytes between the local tty (stdin_fd) and the websocket.

    Returns a reason string describing why the session ended. For the first
    three the caller should NOT reconnect (see ENDED_REASONS):
      "exited"       -- the remote shell exited (server closed with
                        CLOSE_SHELL_EXITED, e.g. you hit Ctrl-D / typed exit).
      "quit"         -- the user asked to quit with the ``~.`` escape.
      "eof"          -- local stdin reached EOF.
      "disconnected" -- the connection dropped (TCP EOF, an abnormal close, or
                        our keepalive ping went unanswered for too long). The
                        caller should reconnect.

    ``old_termios`` is the cooked-mode terminal state, restored around a
    ``~^Z`` suspend so the user's job-control shell behaves normally.
    """
    rows, cols = term_size(stdin_fd)
    ws.send_text(json.dumps({"type": "resize", "rows": rows, "cols": cols,
                             "term": os.environ.get("TERM", "xterm-256color")}))

    winch = {"flag": False}

    def on_winch(signum, frame):
        winch["flag"] = True

    old_winch = signal.signal(signal.SIGWINCH, on_winch)
    escapes = EscapeFilter()
    # Liveness tracking: any inbound byte (data, pong, ping) proves the link is
    # alive. If nothing arrives for DEAD_AFTER seconds despite our pings, the
    # link is wedged -- bail out and reconnect rather than waiting for a TCP
    # write to eventually fail.
    last_recv = time.monotonic()
    last_ping = last_recv
    try:
        while True:
            if winch["flag"]:
                winch["flag"] = False
                rows, cols = term_size(stdin_fd)
                ws.send_text(json.dumps({"type": "resize", "rows": rows, "cols": cols}))

            try:
                readable, _, _ = select.select([stdin_fd, ws], [], [], 1)
            except (select.error, InterruptedError) as e:
                if getattr(e, "errno", None) == errno.EINTR or (e.args and e.args[0] == errno.EINTR):
                    continue
                raise

            now = time.monotonic()

            # Process anything the server sent FIRST, so a pending close frame
            # (especially CLOSE_SHELL_EXITED) is never misread as a dead link by
            # the keepalive check below, and so inbound bytes refresh liveness.
            if ws in readable:
                if not ws.recv_into_buffer():
                    return "disconnected"  # TCP EOF: treat as a dropped link
                last_recv = now
                for opcode, payload in ws.frames():
                    if opcode == WebSocket.OP_CLOSE:
                        # The remote shell exited (Ctrl-D / logout) only when
                        # the server says so with its dedicated close code. Any
                        # other code (generic close, server shutdown, error) or
                        # none means we should recover by reconnecting.
                        code = (payload[0] << 8) | payload[1] if len(payload) >= 2 else None
                        if code == WebSocket.CLOSE_SHELL_EXITED:
                            return "exited"
                        return "disconnected"
                    if opcode == WebSocket.OP_PING:
                        ws.pong(payload)
                        continue
                    if opcode == WebSocket.OP_PONG:
                        continue  # liveness already credited via last_recv
                    if opcode in (WebSocket.OP_TEXT, WebSocket.OP_BINARY):
                        handle_server_message(payload)

            # Keepalive: declare a silent link dead, else ping if one is due.
            if now - last_recv > DEAD_AFTER:
                return "disconnected"  # silent link: no traffic despite pings
            if now - last_ping >= PING_INTERVAL:
                ws.ping()
                last_ping = now

            if stdin_fd in readable:
                try:
                    data = os.read(stdin_fd, 65536)
                except OSError:
                    data = b""
                if not data:
                    return "eof"  # local EOF (e.g. Ctrl-D at a closed stdin)
                forward, actions = escapes.feed(data)
                # Forward typed-through bytes BEFORE acting on any escape, so
                # e.g. "echo hi\n~." still delivers the line before we quit.
                if forward:
                    ws.send_text(json.dumps({"type": "input",
                                             "data": forward.decode("utf-8", "surrogateescape")}))
                for action in actions:
                    if action == "quit":
                        log("exe-ssh: closed (escape ~.).")
                        return "quit"
                    elif action == "help":
                        sys.stderr.write(ESCAPE_HELP)
                        sys.stderr.flush()
                    elif action == "suspend":
                        suspend(stdin_fd, old_termios)
                        # Resuming: the foreground size may have changed and a
                        # ping is overdue, so refresh both.
                        winch["flag"] = True
                        last_recv = last_ping = time.monotonic()
    finally:
        signal.signal(signal.SIGWINCH, old_winch)


def suspend(stdin_fd, old_termios):
    """Suspend exe-ssh (``~^Z``), like ssh(1). Restore cooked-mode terminal,
    stop ourselves with SIGTSTP so the user's shell takes over, then re-enter
    raw mode when we're foregrounded again with ``fg``."""
    log("exe-ssh: suspended; resume with 'fg'.")
    termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_termios)
    # Force the default SIGTSTP disposition so the kernel actually stops us,
    # in case anything installed a handler. SIGCONT already resumes us by
    # default, so leave it alone.
    old_tstp = signal.signal(signal.SIGTSTP, signal.SIG_DFL)
    try:
        os.kill(os.getpid(), signal.SIGTSTP)
    finally:
        # Back in the foreground: restore the handler and raw mode. Use
        # TCSADRAIN (not setraw's default TCSAFLUSH) so type-ahead survives.
        signal.signal(signal.SIGTSTP, old_tstp)
        tty.setraw(stdin_fd, termios.TCSADRAIN)


def wait_for_retry(stdin_fd):
    """Block until the user presses r (retry, returns True) or Ctrl-C (quit,
    returns False). The terminal is raw, so Ctrl-C arrives as a byte."""
    banner("\U0001f511 signing failed \u2014 press r to retry (Ctrl-C to quit)",
           color=YELLOW, replace=True)
    while True:
        b = os.read(stdin_fd, 1)
        if b in (b"r", b"R"):
            return True
        if b in (b"\x03", b""):
            return False


def handle_server_message(payload):
    try:
        msg = json.loads(payload)
    except ValueError:
        return
    if msg.get("type") == "output":
        raw = base64.b64decode(msg.get("data", ""))
        os.write(sys.stdout.fileno(), raw)


# Ways run_session can end that mean "don't reconnect".
ENDED_REASONS = ("exited", "quit", "eof")


class ConnectError(Exception):
    """The first connection attempt failed and won't be retried."""


def attach(connect, stdin_fd, label=None, boot_timeout=0, kill_note=None):
    """Run the interactive session, reconnecting whenever the link drops.

    connect() opens a fresh WebSocket (re-signing its token each time). The
    first connect is retried for up to boot_timeout seconds (e.g. while a new
    VM boots), after which it raises ConnectError. label names the VM in
    status banners; kill_note is logged if SIGTERM/SIGHUP kills us.

    Returns why the session ended: one of ENDED_REASONS, "interrupted"
    (Ctrl-C/SIGINT), or "gave-up" (the user quit at the signing prompt).
    """
    old_termios = termios.tcgetattr(stdin_fd)

    def restore_and_exit(signum, frame):
        # Restore the local terminal before dying on SIGTERM/SIGHUP so we
        # don't leave the user's shell stuck in raw mode.
        termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_termios)
        sys.stderr.write("\r\n")
        if kill_note:
            log(kill_note)
        os._exit(143)

    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, restore_and_exit)

    deadline = time.monotonic() + boot_timeout
    backoff = 0.5
    first = True
    try:
        while True:
            try:
                ws = connect()
            except (OSError, WSError, ssl.SSLError) as e:
                if first:
                    if time.monotonic() >= deadline:
                        raise ConnectError(f"connect failed: {e}")
                    # Still in cooked mode, so Ctrl-C interrupts this wait.
                    banner(f"waiting for {label} to come up… (Ctrl-C to quit)",
                           color=YELLOW, replace=True)
                    time.sleep(1)
                    continue
                log(f"exe-ssh: reconnect failed ({e}); retrying in {backoff:.1f}s")
                time.sleep(backoff)
                backoff = min(backoff * 2, 10)
                continue
            except SignError as e:
                if first:
                    raise ConnectError(str(e))
                # A refusing agent (e.g. a hardware key wanting a touch) is
                # expected; only show ssh-keygen's reason for anything else.
                if e.reason and "agent refused operation" not in e.reason:
                    log(f"exe-ssh: {e.reason}")
                if not wait_for_retry(stdin_fd):
                    return "gave-up"
                continue

            backoff = 0.5
            if first:
                # Raw mode only once connected, so the first connect (and any
                # boot wait) can still be interrupted with Ctrl-C.
                tty.setraw(stdin_fd)
            else:
                banner("✓ reconnected", color=GREEN)
            first = False
            reason = "disconnected"
            try:
                reason = run_session(ws, stdin_fd, old_termios)
            except (OSError, WSError, ssl.SSLError) as e:
                # Mid-session network failure: fall through to reconnect
                # rather than dumping a traceback. This is the common case
                # the auto-reconnect feature exists for.
                log(f"exe-ssh: connection lost ({e})")
            finally:
                ws.close()

            if reason in ENDED_REASONS:
                # The remote shell exited (Ctrl-D / logout) or the user asked
                # to quit (~.). Reconnecting would just spawn a fresh shell, so
                # quit instead -- this matches what ssh(1) does.
                log("exe-ssh: session ended.")
                return reason

            to = f" to {label}" if label else ""
            banner(f"⚡ connection lost{to} — reconnecting… (Ctrl-C to quit)",
                   color=YELLOW)
            time.sleep(0.3)
    except KeyboardInterrupt:
        return "interrupted"
    finally:
        termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_termios)
        sys.stderr.write("\r\n")


def parse_vm(arg):
    """Split a VM argument into (name, base): a bare name like willow-wind
    means the default exe.xyz base; willow-wind.example.com names it."""
    name, _, base = arg.partition(".")
    base = base or "exe.xyz"
    # Validate before interpolating into HTTP headers and namespaces, so they
    # can't smuggle CRLF or other junk.
    for label, val in (("vm", name), ("host", base)):
        if not val or any(c in val for c in "\r\n /\\:@?#") or val != val.strip():
            sys.exit(f"error: invalid {label}: {val!r}")
    return name, base


def add_hidden_test_args(parser):
    # Hidden knobs for testing against a local non-TLS stack on a random port.
    # Not for production use; deliberately undocumented.
    parser.add_argument("--port", type=int, default=443, help=argparse.SUPPRESS)
    parser.add_argument("--plaintext", action="store_true",
                        help=argparse.SUPPRESS)
    parser.add_argument("--connect-host", default=None, help=argparse.SUPPRESS)


def terminal_connector(args, host, key_path, session):
    """Return a connect() for attach() that opens the terminal WebSocket for
    `session` on `host`, signing a fresh token each time."""
    namespace = f"v0@{host}"
    path = f"/terminal/ws/experimental-exe-ssh?{urlencode({'name': session})}"
    insecure = os.environ.get("EXE_SSH_INSECURE") == "1"

    def connect():
        headers = {"Authorization": f"Bearer {generate_token(key_path, namespace)}"}
        return WebSocket.connect(host, args.port, path, headers, insecure,
                                 plaintext=args.plaintext,
                                 connect_host=args.connect_host)
    return connect


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="exe-ssh",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="An SSH-ish interactive terminal for an exe.dev VM, over "
                    "HTTPS (no port 22). The session is persistent and the "
                    "client auto-reconnects.",
        epilog="escape sequences (typed right after Enter, like ssh):\n"
               "  ~.   terminate the connection\n"
               "  ~^Z  suspend exe-ssh (resume with 'fg')\n"
               "  ~~   send a literal '~'\n"
               "  ~?   list these sequences")
    parser.add_argument("vm", help="VM name (e.g. willow-wind), or a "
                                   "fully-qualified box host (e.g. "
                                   "willow-wind.exe.xyz)")
    parser.add_argument("session", nargs="?", default=None,
                        help="named terminal session to attach to "
                             "(default: a random color name)")
    parser.add_argument("-l", "--list", action="store_true",
                        help="list this VM's existing terminal sessions and exit")
    parser.add_argument("-i", "--key", metavar="PATH", default=None,
                        help="SSH private key to sign with "
                             "(default: ask ssh -G)")
    add_hidden_test_args(parser)
    args = parser.parse_args(argv)

    # The VM arg is either a bare name (-> <name>.xterm.exe.xyz) or a
    # fully-qualified box host like <name>.exe.xyz (-> <name>.xterm.exe.xyz).
    name, base = parse_vm(args.vm)

    # The terminal endpoint is scoped to its own namespace (v0@<vm>.xterm.<base>),
    # distinct from the general VM-proxy namespace (v0@<vm>.<base>): the token
    # is bound to exactly this VM's terminal.
    host = f"{name}.xterm.{base}"
    namespace = f"v0@{host}"
    key_path = find_key(args.key, host)
    insecure = os.environ.get("EXE_SSH_INSECURE") == "1"

    def fetch_sessions():
        headers = {"Authorization": f"Bearer {generate_token(key_path, namespace)}"}
        resp = http_get_json(host, args.port, "/terminal/sessions", headers,
                             insecure, plaintext=args.plaintext,
                             connect_host=args.connect_host)
        sessions = resp.get("sessions") if isinstance(resp, dict) else None
        if not isinstance(sessions, list):
            raise WSError("unexpected sessions response")
        names = []
        for s in sessions:
            name = s.get("name") if isinstance(s, dict) else None
            if isinstance(name, str) and name:
                names.append(name)
        return names

    # --list: print the VM's existing sessions and exit. This is a plain GET,
    # so it works without a tty (e.g. piped into a script).
    if args.list:
        try:
            names = fetch_sessions()
        except (OSError, WSError, SignError, ssl.SSLError, ValueError) as e:
            sys.exit(f"error: could not list sessions: {e}")
        if names:
            for n in names:
                print(n)
        else:
            log(f"exe-ssh: no terminal sessions on {args.vm}.")
        return

    # Attaching needs an interactive terminal; check before doing any network
    # work (e.g. the best-effort session list below).
    if not sys.stdin.isatty():
        sys.exit("error: stdin is not a tty; this client needs an interactive terminal")

    # Pick the session: explicit arg, or a random color name (avoiding names
    # already in use when we can enumerate them).
    session = args.session
    if session is None:
        existing = []
        try:
            existing = fetch_sessions()
        except (OSError, WSError, SignError, ssl.SSLError, ValueError):
            pass  # best-effort; fall back to a plain random name
        session = random_session_name(avoid=existing)
        log(f"exe-ssh: new session '{session}' (pass a name to reattach; -l to list)")
    if not re.fullmatch(r"[a-zA-Z0-9-]+", session):
        sys.exit(f"error: invalid session name: {session!r} "
                 "(letters, digits and dashes only)")

    log(f"exe-ssh: connecting to {args.vm} (session '{session}') over https...")
    connect = terminal_connector(args, host, key_path, session)
    try:
        attach(connect, sys.stdin.fileno())
    except ConnectError as e:
        sys.exit(f"error: {e}")


# ---------------------------------------------------------------------------
# exe-clone: ephemeral clones
# ---------------------------------------------------------------------------

# How long to keep retrying the first connect while a fresh clone boots.
CLONE_BOOT_TIMEOUT = 90
# Copying a VM can take a while; give the cp request more than the default.
CLONE_REQUEST_TIMEOUT = 300
CLONE_SUFFIX_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789"


class APIError(Exception):
    pass


def clone_name(src):
    """Name the clone after its source plus a random suffix, so it's
    recognisable (e.g. in `ssh exe.dev ls`) if it has to be removed by hand."""
    return f"{src}-" + "".join(random.choice(CLONE_SUFFIX_CHARS) for _ in range(4))


def parse_clone_response(body, fallback):
    """The VM name from a `cp` API response, or fallback if it has none."""
    try:
        data = json.loads(body.decode("utf-8"))
    except ValueError:
        return fallback
    if isinstance(data, dict):
        for key in ("vm_name", "name", "vm"):
            val = data.get(key)
            if isinstance(val, str) and re.fullmatch(r"[a-zA-Z0-9-]+", val):
                return val
    return fallback


def confirm(prompt, default=False):
    """Ask a yes/no question on the (cooked-mode) terminal. Enter picks
    default; Ctrl-C and EOF always mean no."""
    sys.stderr.write(prompt)
    sys.stderr.flush()
    try:
        line = sys.stdin.readline()
    except KeyboardInterrupt:
        line = ""
    if not line:
        sys.stderr.write("\n")
        return False
    answer = line.strip().lower()
    if not answer:
        return default
    return answer in ("y", "yes")


def clone_main(argv=None):
    parser = argparse.ArgumentParser(
        prog="exe-clone",
        description="Clone an exe.dev VM, open a terminal on the clone, and "
                    "offer to remove the clone when you exit its shell. The "
                    "connection auto-reconnects like exe-ssh.")
    parser.add_argument("vm", help="VM to clone (e.g. willow-wind)")
    parser.add_argument("--rm", action="store_true",
                        help="remove the clone without asking when you exit "
                             "its shell")
    parser.add_argument("-i", "--key", metavar="PATH", default=None,
                        help="SSH private key to sign with "
                             "(default: ask ssh -G)")
    add_hidden_test_args(parser)
    parser.add_argument("--api-host", default="exe.dev", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    src, base = parse_vm(args.vm)
    if not sys.stdin.isatty():
        sys.exit("error: stdin is not a tty; this client needs an interactive terminal")

    clone = clone_name(src)
    host = f"{clone}.xterm.{base}"
    key_path = find_key(args.key, host)
    insecure = os.environ.get("EXE_SSH_INSECURE") == "1"
    cleanup = f"ssh {args.api_host} rm {clone}"

    def api(cmd, timeout=CONNECT_TIMEOUT):
        """Run an exe.dev command via POST /exec with a token that may run
        only that command. A failed signature offers a retry."""
        while True:
            try:
                token = generate_token(key_path, f"v0@{args.api_host}",
                                       cmds=[cmd.split()[0]])
                break
            except SignError as e:
                log(f"exe-ssh: {e.reason or e}")
                if not confirm("exe-ssh: signing failed — retry? [Y/n] ", default=True):
                    raise
        headers = {"Authorization": f"Bearer {token}",
                   "Content-Type": "text/plain"}
        code, body = http_request("POST", args.api_host, args.port, "/exec",
                                  headers, insecure, body=cmd.encode("utf-8"),
                                  plaintext=args.plaintext,
                                  connect_host=args.connect_host, timeout=timeout)
        if code != 200:
            raise APIError(f"HTTP {code}: {body.decode('utf-8', 'replace').strip()}")
        return body

    log(f"exe-ssh: cloning {src} → {clone}…")
    try:
        body = api(f"cp {src} {clone}", timeout=CLONE_REQUEST_TIMEOUT)
    except (OSError, WSError, APIError, SignError, ssl.SSLError,
            KeyboardInterrupt) as e:
        log(f"exe-ssh: if {clone} was created anyway, remove it with: {cleanup}")
        sys.exit(f"error: could not clone {src}: {e or 'interrupted'}")
    if parse_clone_response(body, clone) != clone:
        # Unexpected, but don't connect to (or offer to remove) a VM whose
        # name we can't trust.
        sys.exit(f"error: server created a clone with an unexpected name; "
                 f"check `ssh {args.api_host} ls`")

    # Print the manual cleanup now, so it's on screen whatever happens later.
    log(f"exe-ssh: created clone {clone}; to remove it yourself: {cleanup}")
    log(f"exe-ssh: connecting to clone {clone} (from {src}) over https...")
    connect = terminal_connector(args, host, key_path, random_session_name())
    try:
        reason = attach(connect, sys.stdin.fileno(), label=f"clone {clone}",
                        boot_timeout=CLONE_BOOT_TIMEOUT,
                        kill_note=f"exe-ssh: kept clone {clone}; remove it with: {cleanup}")
    except ConnectError as e:
        # The clone never became usable, so there's nothing on it to lose:
        # treat this like a deliberate exit and offer to remove it.
        log(f"exe-ssh: {e}")
        reason = "failed"

    if reason not in ("exited", "quit", "failed"):
        # Interrupted, gave up signing, or stdin EOF: not a deliberate exit
        # from the shell, so never remove anything.
        log(f"exe-ssh: kept clone {clone}; remove it with: {cleanup}")
        return

    if not (args.rm or confirm(f"exe-ssh: remove clone {clone}? [y/N] ")):
        log(f"exe-ssh: kept clone {clone}; remove it with: {cleanup}")
        return

    log(f"exe-ssh: removing {clone}…")
    try:
        api(f"rm {clone}", timeout=CLONE_REQUEST_TIMEOUT)
    except (OSError, WSError, APIError, SignError, ssl.SSLError,
            KeyboardInterrupt) as e:
        banner(f"could not remove clone {clone}: {e or 'interrupted'}", color=RED)
        log(f"exe-ssh: remove it yourself with: {cleanup}")
        sys.exit(1)
    log(f"exe-ssh: removed {clone}.")


if __name__ == "__main__":
    main()
