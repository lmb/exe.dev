import base64
import http.server
import io
import json
import re
import threading
import unittest
from unittest import mock

from exe_ssh import cli


class CLITest(unittest.TestCase):
    def test_random_session_avoids_existing_names(self):
        with mock.patch.object(cli.random, "choice", side_effect=lambda names: names[0]):
            self.assertNotEqual(cli.random_session_name(["amber"]), "amber")

    def test_random_session_falls_back_when_palette_is_exhausted(self):
        with mock.patch.object(cli.random, "choice", side_effect=lambda names: names[0]):
            self.assertEqual(cli.random_session_name(cli.SESSION_COLORS), "amber")


def decode_token_payload(token):
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


class TokenTest(unittest.TestCase):
    ARMORED = (b"-----BEGIN SSH SIGNATURE-----\n"
               + base64.b64encode(b"sig") + b"\n-----END SSH SIGNATURE-----\n")

    def test_token_without_cmds(self):
        with mock.patch.object(cli.subprocess, "check_output", return_value=self.ARMORED):
            perms = decode_token_payload(cli.generate_token("k", "v0@x"))
        self.assertEqual(set(perms), {"exp"})

    def test_token_with_cmds(self):
        with mock.patch.object(cli.subprocess, "check_output", return_value=self.ARMORED):
            perms = decode_token_payload(cli.generate_token("k", "v0@x", cmds=["rm"]))
        self.assertEqual(perms["cmds"], ["rm"])


class HTTPRequestTest(unittest.TestCase):
    def test_post_sends_body(self):
        received = {}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers["Content-Length"])
                received["body"] = self.rfile.read(n)
                received["auth"] = self.headers["Authorization"]
                out = b'{"vm_name": "x"}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=srv.handle_request, daemon=True).start()
        try:
            code, body = cli.http_request(
                "POST", "exe.dev", srv.server_port, "/exec",
                {"Authorization": "Bearer t"}, False, body=b"cp a b",
                plaintext=True, connect_host="127.0.0.1")
        finally:
            srv.server_close()
        self.assertEqual(code, 200)
        self.assertEqual(body, b'{"vm_name": "x"}')
        self.assertEqual(received, {"body": b"cp a b", "auth": "Bearer t"})


class CloneHelpersTest(unittest.TestCase):
    def test_clone_name(self):
        self.assertRegex(cli.clone_name("willow-wind"), r"^willow-wind-[a-z0-9]{4}$")

    def test_parse_clone_response(self):
        self.assertEqual(cli.parse_clone_response(b'{"vm_name": "a-b"}', "f"), "a-b")
        self.assertEqual(cli.parse_clone_response(b'{"name": "a"}', "f"), "a")
        self.assertEqual(cli.parse_clone_response(b"not json", "f"), "f")
        self.assertEqual(cli.parse_clone_response(b'{"vm_name": "a b"}', "f"), "f")

    def test_confirm(self):
        cases = [("y\n", False, True), ("YES\n", False, True), ("\n", False, False),
                 ("\n", True, True), ("n\n", True, False), ("", True, False)]
        for line, default, want in cases:
            with mock.patch.object(cli.sys, "stdin", io.StringIO(line)), \
                    mock.patch.object(cli.sys, "stderr", io.StringIO()):
                self.assertEqual(cli.confirm("? ", default=default), want, (line, default))


class CloneMainTest(unittest.TestCase):
    """clone_main's decision of whether to remove the clone."""

    def run_clone(self, argv, reason, answer=False, rm_status=200):
        commands = []

        def fake_request(method, host, port, path, headers, insecure, body=None, **kw):
            commands.append(body.decode())
            if body.startswith(b"cp "):
                return 200, json.dumps({"vm_name": body.split()[2].decode()}).encode()
            return rm_status, b"nope"

        def fake_attach(*a, **kw):
            if isinstance(reason, Exception):
                raise reason
            return reason

        stderr = io.StringIO()
        with mock.patch.object(cli, "find_key", return_value="k"), \
                mock.patch.object(cli, "generate_token", return_value="t"), \
                mock.patch.object(cli, "http_request", side_effect=fake_request), \
                mock.patch.object(cli, "attach", side_effect=fake_attach), \
                mock.patch.object(cli, "confirm", return_value=answer) as confirm, \
                mock.patch.object(cli.sys, "stdin") as stdin, \
                mock.patch.object(cli.sys, "stderr", stderr):
            stdin.isatty.return_value = True
            stdin.fileno.return_value = 0
            try:
                cli.clone_main(argv)
                code = 0
            except SystemExit as e:
                code = e.code
        return commands, confirm, code, stderr.getvalue()

    def test_clones_with_prefixed_name(self):
        commands, _, _, _ = self.run_clone(["willow-wind"], "exited")
        self.assertRegex(commands[0], r"^cp willow-wind willow-wind-[a-z0-9]{4}$")

    def test_exit_prompts_and_keeps_by_default(self):
        commands, confirm, _, out = self.run_clone(["vm"], "exited", answer=False)
        confirm.assert_called_once()
        self.assertEqual(len(commands), 1)
        self.assertIn("kept clone", out)

    def test_exit_prompts_and_removes_on_yes(self):
        commands, _, code, _ = self.run_clone(["vm"], "quit", answer=True)
        clone = commands[0].split()[2]
        self.assertEqual(commands[1], f"rm {clone}")
        self.assertEqual(code, 0)

    def test_rm_flag_skips_prompt(self):
        commands, confirm, _, _ = self.run_clone(["vm", "--rm"], "exited")
        confirm.assert_not_called()
        self.assertTrue(commands[1].startswith("rm "))

    def test_non_deliberate_endings_keep_clone_even_with_rm(self):
        for reason in ("interrupted", "gave-up", "eof"):
            commands, confirm, _, out = self.run_clone(["vm", "--rm"], reason)
            confirm.assert_not_called()
            self.assertEqual(len(commands), 1, reason)
            self.assertIn("kept clone", out)

    def test_connect_failure_offers_removal(self):
        commands, confirm, _, _ = self.run_clone(
            ["vm"], cli.ConnectError("connect failed"), answer=True)
        confirm.assert_called_once()
        self.assertTrue(commands[1].startswith("rm "))

    def test_failed_remove_prints_manual_cleanup(self):
        commands, _, code, out = self.run_clone(["vm", "--rm"], "exited", rm_status=500)
        clone = commands[0].split()[2]
        self.assertEqual(code, 1)
        self.assertIn(f"could not remove clone {clone}", out)
        self.assertIn(f"ssh exe.dev rm {clone}", out)


if __name__ == "__main__":
    unittest.main()
