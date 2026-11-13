"""`haprion.http01_check`, its helper, its command and the web's client (B496, B499)."""

from __future__ import annotations

import errno
import functools
import http.client
import http.server
import io
import json
import os
import signal
import tempfile
import threading
import unittest
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit

from haprion import exit_codes, helper_socket, http01_check, http01_check_socket
from haprion.cli import http01_check as command
from haprion.cli import http01_check_helper as helper
from haprion.config import load_policy
from haprion.http01_check import Check, CheckError, Reply
from tests.contract_schema import assert_contract

NAME = "app.example.com"
ADDRESS = "192.0.2.80"
POLICY = """\
schema_version: 1
cluster_file: {root}/clusters.yaml
config_root: {root}/config
publish_root: {root}/publish
validation_certs_root: {root}/validation
acme:
  webroot: {root}/webroot
"""


def resolved(_name: str) -> list[str]:
    return [ADDRESS, "192.0.2.81"]


def unresolved(_name: str) -> list[str]:
    return []


class Webroot:
    """A fetch that reads the webroot the way the cluster's ACME rule would serve it."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.seen: list[Path] = []
        self.urls: list[str] = []

    def __call__(self, url: str, _timeout: float) -> Reply:
        self.urls.append(url)
        path = self.root / urlsplit(url).path.lstrip("/")
        self.seen.append(path)
        if path.is_file():
            return Reply(200, path.read_bytes(), None, ADDRESS)
        return Reply(404, b"not found", None, ADDRESS)


class Scenario(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.webroot = self.root / "webroot"
        self.webroot.mkdir()

    def left(self) -> list[str]:
        return sorted(str(p.relative_to(self.webroot)) for p in self.webroot.rglob("*"))


class TheName(unittest.TestCase):
    def test_one_name_lowercased(self) -> None:
        self.assertEqual(http01_check.parse_name(" App.Example.COM "), NAME)

    def test_a_trailing_dot_is_the_same_name(self) -> None:
        """A fully qualified name: the form drops the dot, and so does the command."""

        self.assertEqual(http01_check.parse_name("App.Example.com."), NAME)
        with self.assertRaises(CheckError):
            http01_check.parse_name(".")

    def test_a_wildcard_is_refused_with_the_method_that_proves_it(self) -> None:
        with self.assertRaises(CheckError) as caught:
            http01_check.parse_name("*.example.com")
        self.assertIn("DNS-01", str(caught.exception))
        self.assertEqual(caught.exception.code, "bad_input")

    def test_no_name_is_said_in_words_not_as_a_parameter(self) -> None:
        """An empty domain field reached the helper as `parameters.name must be a string`."""

        for text in ("", "   "):
            with self.subTest(text=text), self.assertRaises(CheckError) as caught:
                http01_check.parse_name(text)
            self.assertEqual(
                str(caught.exception), "write the name the certificate is for, then check it"
            )

    def test_what_is_not_a_domain_name_is_refused(self) -> None:
        for text in (
            "localhost",
            "192.0.2.80",
            "a b.example.com",
            "",
            "example.com/x",
            #
            # The resolver reads these as addresses (inet_aton), a CA does not
            # issue for them.
            #
            "127.1",
            "10.1",
            "192.0.2.010",
            "0x7f.1",
            "app.example.0x1",
        ):
            with self.subTest(text=text), self.assertRaises(CheckError):
                http01_check.parse_name(text)


class TheCheck(Scenario):
    def test_the_file_comes_back_and_is_gone_afterwards(self) -> None:
        fetch = Webroot(self.webroot)
        found = http01_check.check(NAME, self.webroot, fetch=fetch, resolve=resolved)
        self.assertEqual(found, Check(NAME, "reached", ADDRESS, None, None))
        self.assertTrue(fetch.urls[0].startswith(f"http://{NAME}/.well-known/acme-challenge/"))
        self.assertEqual(self.left(), [])

    def test_certbots_directories_and_files_are_left_as_they_were(self) -> None:
        challenge = self.webroot / ".well-known" / "acme-challenge"
        challenge.mkdir(parents=True)
        (challenge / "certbots").write_text("x")
        found = http01_check.check(
            NAME, self.webroot, fetch=Webroot(self.webroot), resolve=resolved
        )
        self.assertEqual(found.answer, "reached")
        self.assertEqual(
            self.left(),
            [".well-known", ".well-known/acme-challenge", ".well-known/acme-challenge/certbots"],
        )

    def test_the_file_is_world_readable_for_the_web_server(self) -> None:
        modes: list[int] = []

        def fetch(url: str, timeout: float) -> Reply:
            path = self.webroot / urlsplit(url).path.lstrip("/")
            modes.extend((path.stat().st_mode & 0o777, path.parent.stat().st_mode & 0o777))
            return Webroot(self.webroot)(url, timeout)

        http01_check.check(NAME, self.webroot, fetch=fetch, resolve=resolved)
        self.assertEqual(modes, [0o644, 0o755])

    def test_a_name_that_does_not_resolve_writes_nothing(self) -> None:
        fetch = Webroot(self.webroot)
        found = http01_check.check(NAME, self.webroot, fetch=fetch, resolve=unresolved)
        self.assertEqual(found, Check(NAME, "unresolved", None, None, None))
        self.assertEqual(fetch.urls, [])
        self.assertEqual(found.sentence(), f"{NAME} does not resolve from this manager.")

    def test_another_service_is_said_with_its_status(self) -> None:
        for reply, said in (
            (Reply(404, b"", None, ADDRESS), "404 for the test file"),
            (Reply(200, b"<html>welcome</html>", None, ADDRESS), "200 without the test file"),
            (Reply(302, b"", None, ADDRESS), "302 for the test file"),
        ):
            with self.subTest(status=reply.status):
                found = http01_check.check(
                    NAME, self.webroot, fetch=mock.Mock(return_value=reply), resolve=resolved
                )
                self.assertEqual(found.answer, "other")
                self.assertEqual(found.status, reply.status)
                self.assertEqual(
                    found.sentence(),
                    f"Another service answers: {NAME} is {ADDRESS}, which answered {said}. "
                    "Checked from this manager, not from the internet.",
                )
                self.assertEqual(self.left(), [])

    def test_the_address_is_the_one_that_answered(self) -> None:
        found = http01_check.check(
            NAME,
            self.webroot,
            fetch=lambda _u, _t: Reply(404, b"", None, "192.0.2.81"),
            resolve=resolved,
        )
        self.assertEqual(found.address, "192.0.2.81")

    def test_nothing_answering_is_silent_with_what_the_connection_said(self) -> None:
        for error, problem in (
            (ConnectionRefusedError(), "port 80 refused the connection"),
            (TimeoutError(), "port 80 did not answer in time"),
            (OSError(113, "No route to host"), "port 80 could not be reached (No route to host)"),
            (http.client.BadStatusLine("x"), "port 80 did not answer with HTTP (BadStatusLine)"),
        ):
            with self.subTest(error=type(error).__name__):

                def fetch(_url: str, _timeout: float, error: Exception = error) -> Reply:
                    raise error

                found = http01_check.check(NAME, self.webroot, fetch=fetch, resolve=resolved)
                self.assertEqual(found, Check(NAME, "silent", ADDRESS, None, problem))
                self.assertEqual(
                    found.sentence(),
                    f"Nothing answers: {NAME} is {ADDRESS}, and {problem}. "
                    "Checked from this manager, not from the internet.",
                )
                self.assertEqual(self.left(), [])

    def test_the_file_is_removed_when_the_fetch_fails_unexpectedly(self) -> None:
        def fetch(_url: str, _timeout: float) -> Reply:
            raise RuntimeError("a bug")

        with self.assertRaises(RuntimeError):
            http01_check.check(NAME, self.webroot, fetch=fetch, resolve=resolved)
        self.assertEqual(self.left(), [])

    def test_the_file_is_removed_when_systemd_stops_the_helper(self) -> None:
        """RuntimeMaxSec ends a check a dripping server holds: SIGTERM, then the finally."""

        def fetch(url: str, _timeout: float) -> Reply:
            self.assertEqual(len(self.left()), 3)
            os.kill(os.getpid(), signal.SIGTERM)
            return Reply(404, b"", None, ADDRESS)

        before = signal.getsignal(signal.SIGTERM)
        with self.assertRaises(SystemExit) as caught:
            http01_check.check(NAME, self.webroot, fetch=fetch, resolve=resolved)
        self.assertEqual(caught.exception.code, 128 + signal.SIGTERM)
        self.assertEqual(self.left(), [])
        self.assertIs(signal.getsignal(signal.SIGTERM), before)

    def test_the_whole_check_has_one_deadline(self) -> None:
        times = iter([0.0, 0.0, http01_check.TOTAL_SECONDS + 1])
        timeouts: list[float] = []

        def fetch(url: str, timeout: float) -> Reply:
            timeouts.append(timeout)
            return Reply(301, b"", f"https://{NAME}/{urlsplit(url).path}", ADDRESS)

        found = http01_check.check(
            NAME, self.webroot, fetch=fetch, resolve=resolved, clock=lambda: next(times)
        )
        self.assertEqual(timeouts, [http01_check.CONNECT_SECONDS])
        self.assertEqual(found.answer, "other")
        self.assertEqual(
            found.problem, f"redirected to https://{NAME}/, where port 443 did not answer in time"
        )


class TheRedirects(Scenario):
    def test_a_redirect_to_https_is_followed_as_the_ca_follows_it(self) -> None:
        served = Webroot(self.webroot)

        def fetch(url: str, timeout: float) -> Reply:
            if url.startswith("http://"):
                return Reply(301, b"", "https://" + url.removeprefix("http://"), ADDRESS)
            return Reply(served(url, timeout).status, served(url, timeout).body, None, "192.0.2.99")

        found = http01_check.check(NAME, self.webroot, fetch=fetch, resolve=resolved)
        self.assertEqual(found, Check(NAME, "reached", ADDRESS, None, None))

    def test_a_redirect_the_ca_would_not_follow_is_another_service(self) -> None:
        for location in (f"http://{NAME}:8080/x", "ftp://example.com/x", "/"):
            with self.subTest(location=location):
                seen: list[str] = []

                def fetch(
                    url: str, _timeout: float, location: str = location, seen: list[str] = seen
                ) -> Reply:
                    seen.append(url)
                    if len(seen) > 1:
                        return Reply(200, b"<html>home</html>", None, ADDRESS)
                    return Reply(301, b"", location, ADDRESS)

                found = http01_check.check(NAME, self.webroot, fetch=fetch, resolve=resolved)
                self.assertEqual(found.answer, "other")
                if location == "/":
                    self.assertEqual(seen[1], f"http://{NAME}/")
                    self.assertEqual(found.status, 200)
                else:
                    self.assertEqual(len(seen), 1)
                    self.assertEqual(found.status, 301)

    def test_a_redirect_to_an_address_that_is_not_one_is_another_service(self) -> None:
        for location in (
            "http://x.example.com:99999/",
            "http://x.example.com:abc/",
            "http://[::1/",
        ):
            with self.subTest(location=location):

                def fetch(url: str, _timeout: float, location: str = location) -> Reply:
                    return Reply(301, b"", location, ADDRESS)

                found = http01_check.check(NAME, self.webroot, fetch=fetch, resolve=resolved)
                self.assertEqual((found.answer, found.status), ("other", 301))
                self.assertEqual(found.problem, "redirected to an address that is not one")
                self.assertEqual(self.left(), [])

    def test_a_redirect_to_an_address_is_not_followed_as_the_ca_does_not(self) -> None:
        for location in (
            "http://192.0.2.1/x",
            "http://[2001:db8::1]/x",
            "http://127.1/",
            "http://intranet/",
        ):
            with self.subTest(location=location):
                seen: list[str] = []

                def fetch(
                    url: str, _timeout: float, location: str = location, seen: list[str] = seen
                ) -> Reply:
                    seen.append(url)
                    return Reply(301, b"", location, ADDRESS)

                found = http01_check.check(NAME, self.webroot, fetch=fetch, resolve=resolved)
                self.assertEqual((found.answer, found.status), ("other", 301))
                self.assertEqual(
                    found.problem,
                    "redirected to an address that is not a public domain name,"
                    " which the CA does not follow",
                )
                self.assertEqual(len(seen), 1)

    def test_more_than_ten_redirects_are_said_as_such(self) -> None:
        """The known fault of 2026-11-08: the sentence said "None for the test file"."""

        calls: list[str] = []

        def fetch(url: str, _timeout: float) -> Reply:
            calls.append(url)
            return Reply(302, b"", url, ADDRESS)

        found = http01_check.check(NAME, self.webroot, fetch=fetch, resolve=resolved)
        self.assertEqual(len(calls), http01_check.MAX_REDIRECTS + 1)
        self.assertEqual(found, Check(NAME, "other", ADDRESS, 302, "redirected more than 10 times"))
        self.assertEqual(
            found.sentence(),
            f"Another service answers: {NAME} is {ADDRESS}, which redirected more than 10 times. "
            "Checked from this manager, not from the internet.",
        )
        self.assertNotIn("None", found.sentence())

    def test_a_redirect_that_leads_nowhere_is_another_service_not_silence(self) -> None:
        def fetch(url: str, _timeout: float) -> Reply:
            if url.startswith("https://"):
                raise ConnectionRefusedError
            return Reply(308, b"", "https://" + url.removeprefix("http://"), ADDRESS)

        found = http01_check.check(NAME, self.webroot, fetch=fetch, resolve=resolved)
        self.assertEqual(
            found,
            Check(
                NAME,
                "other",
                ADDRESS,
                308,
                f"redirected to https://{NAME}/, where port 443 refused the connection",
            ),
        )


class TheWebroot(Scenario):
    def test_a_link_in_the_webroot_is_not_followed(self) -> None:
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        (self.webroot / ".well-known").symlink_to(elsewhere)
        with self.assertRaises(CheckError) as caught:
            http01_check.check(NAME, self.webroot, fetch=Webroot(self.webroot), resolve=resolved)
        self.assertEqual(caught.exception.exit_code, exit_codes.CONFIG)
        self.assertEqual(list(elsewhere.iterdir()), [])

    def test_a_link_in_place_of_the_challenge_directory_is_not_followed(self) -> None:
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        (self.webroot / ".well-known").mkdir()
        (self.webroot / ".well-known" / "acme-challenge").symlink_to(elsewhere)
        with self.assertRaises(CheckError):
            http01_check.check(NAME, self.webroot, fetch=Webroot(self.webroot), resolve=resolved)
        self.assertEqual(list(elsewhere.iterdir()), [])
        self.assertTrue((self.webroot / ".well-known" / "acme-challenge").is_symlink())

    def test_a_webroot_that_is_a_link_or_missing_is_refused(self) -> None:
        link = self.root / "link"
        link.symlink_to(self.webroot)
        for webroot in (link, self.root / "missing"):
            with self.subTest(webroot=webroot.name), self.assertRaises(CheckError) as caught:
                http01_check.check(NAME, webroot, fetch=Webroot(self.webroot), resolve=resolved)
            self.assertEqual(caught.exception.code, "dependency_unavailable")
        self.assertEqual(self.left(), [])

    def test_a_webroot_that_cannot_be_written_is_said_before_anything_is_fetched(self) -> None:
        fetch = Webroot(self.webroot)
        with (
            mock.patch("os.mkdir", side_effect=PermissionError(13, "Permission denied")),
            self.assertRaises(CheckError) as caught,
        ):
            http01_check.check(NAME, self.webroot, fetch=fetch, resolve=resolved)
        self.assertIn("could not be written", str(caught.exception))
        self.assertEqual(fetch.urls, [])

    def test_a_webroot_the_sandbox_does_not_open_names_the_step_that_does(self) -> None:
        with (
            mock.patch("os.mkdir", side_effect=OSError(errno.EROFS, "Read-only file system")),
            self.assertRaises(CheckError) as caught,
        ):
            http01_check.check(NAME, self.webroot, fetch=Webroot(self.webroot), resolve=resolved)
        self.assertIn("Read-only file system", str(caught.exception))
        self.assertIn("07-platform-services", str(caught.exception))


@contextmanager
def serving(
    root: Path, handler: type[http.server.BaseHTTPRequestHandler] | None = None
) -> Iterator[int]:
    """A web server on the loopback serving `root`, as nginx serves the webroot."""

    quiet = type(
        "Quiet", (http.server.SimpleHTTPRequestHandler,), {"log_message": lambda *_a: None}
    )
    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0), handler or functools.partial(quiet, directory=str(root))
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class TheFetch(Scenario):
    def test_a_real_server_gives_back_the_file_written_in_the_webroot(self) -> None:
        with serving(self.webroot) as port:

            def fetch(url: str, timeout: float) -> Reply:
                parts = urlsplit(url)
                return http01_check.fetch(f"http://127.0.0.1:{port}{parts.path}", timeout)

            found = http01_check.check(NAME, self.webroot, fetch=fetch, resolve=resolved)
        self.assertEqual(found, Check(NAME, "reached", "127.0.0.1", None, None))
        self.assertEqual(self.left(), [])

    def test_one_get_with_no_redirect_followed(self) -> None:
        class Redirect(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(301)
                self.send_header("Location", "https://app.example.com/next")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *_args: object) -> None:
                pass

        with serving(self.webroot, Redirect) as port:
            reply = http01_check.fetch(f"http://127.0.0.1:{port}/x", 5.0)
        self.assertEqual(reply, Reply(301, b"", "https://app.example.com/next", "127.0.0.1"))

    def test_a_long_page_is_read_no_further_than_its_first_bytes(self) -> None:
        (self.webroot / "big").write_bytes(b"x" * (http01_check.MAX_BODY_BYTES * 4))
        with serving(self.webroot) as port:
            reply = http01_check.fetch(f"http://127.0.0.1:{port}/big", 5.0)
        self.assertEqual(len(reply.body), http01_check.MAX_BODY_BYTES)

    def test_a_closed_port_raises_what_the_check_calls_silence(self) -> None:
        with serving(self.webroot) as port:
            pass
        with self.assertRaises(ConnectionRefusedError):
            http01_check.fetch(f"http://127.0.0.1:{port}/x", 5.0)


def request(name: object = NAME) -> bytes:
    return json.dumps(
        {
            "schema_version": 1,
            "operation": "http01_check",
            "cluster": None,
            "request_id": str(uuid.uuid4()),
            "parameters": {"name": name},
        }
    ).encode()


class TheHelper(Scenario):
    def setUp(self) -> None:
        super().setUp()
        self.policy = self.root / "policy.yaml"
        self.policy.write_text(POLICY.format(root=self.root))
        #
        # The policy is the test's, not root's: read as the helper reads it,
        # without the ownership the installation gives it.
        #
        patch = mock.patch.object(
            helper, "load_policy", functools.partial(load_policy, require_secure=False)
        )
        patch.start()
        self.addCleanup(patch.stop)

    def run_helper(self, body: bytes, **kwargs: object) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = helper.main(
            [],
            input_stream=io.BytesIO(body),
            output_stream=out,
            error_stream=err,
            policy_path=self.policy,
            require_root=False,
            **kwargs,  # type: ignore[arg-type]
        )
        return code, out.getvalue(), err.getvalue()

    def test_the_answer_is_the_contracts(self) -> None:
        code, out, err = self.run_helper(request(), fetch=Webroot(self.webroot), resolve=resolved)
        self.assertEqual(code, 0)
        document = assert_contract("haprion-http01-check", out)
        self.assertEqual(document["result"], Check(NAME, "reached", ADDRESS, None, None).as_dict())
        self.assertEqual(err, f"http01_check: {NAME} reached\n")
        self.assertEqual(self.left(), [])

    def test_every_answer_fits_the_contract(self) -> None:
        for resolve, fetch in (
            (unresolved, Webroot(self.webroot)),
            (resolved, lambda _u, _t: Reply(404, b"", None, ADDRESS)),
            (resolved, mock.Mock(side_effect=ConnectionRefusedError)),
        ):
            with self.subTest(fetch=fetch):
                code, out, _err = self.run_helper(request(), fetch=fetch, resolve=resolve)
                self.assertEqual(code, 0)
                assert_contract("haprion-http01-check", out)

    def test_a_policy_without_a_webroot_is_refused_as_the_installation(self) -> None:
        self.policy.write_text(POLICY.format(root=self.root).partition("acme:")[0])
        code, out, _err = self.run_helper(request(), fetch=Webroot(self.webroot), resolve=resolved)
        self.assertEqual(code, exit_codes.CONFIG)
        document = assert_contract("haprion-http01-check", out)
        self.assertEqual(document["error"]["code"], "dependency_unavailable")
        self.assertIn("acme.webroot", document["error"]["message"])

    def test_a_bad_name_is_refused_as_bad_input(self) -> None:
        for name in ("*.example.com", 7, "x" * 300, ""):
            with self.subTest(name=name):
                code, out, _err = self.run_helper(request(name))
                self.assertEqual(code, exit_codes.REFUSED)
                document = assert_contract("haprion-http01-check", out)
                self.assertEqual(document["error"]["code"], "bad_input")

    def test_only_the_name_is_a_parameter(self) -> None:
        body = json.loads(request())
        body["parameters"]["webroot"] = "/etc"
        code, out, err = self.run_helper(json.dumps(body).encode())
        self.assertNotEqual(code, 0)
        self.assertEqual(out, "")
        self.assertIn("webroot", err)

    def test_the_helper_must_be_root(self) -> None:
        with mock.patch("os.geteuid", return_value=1000):
            code = helper.main(
                [],
                input_stream=io.BytesIO(request()),
                output_stream=io.StringIO(),
                error_stream=io.StringIO(),
                policy_path=self.policy,
            )
        self.assertEqual(code, exit_codes.NOT_ROOT)


class TheCommand(Scenario):
    def setUp(self) -> None:
        super().setUp()
        self.policy = self.root / "policy.yaml"
        self.policy.write_text(POLICY.format(root=self.root))
        #
        # The policy is the test's, not root's: read as the helper reads it,
        # without the ownership the installation gives it.
        #
        patch = mock.patch.object(
            helper, "load_policy", functools.partial(load_policy, require_secure=False)
        )
        patch.start()
        self.addCleanup(patch.stop)

    def run_command(self, *argv: str, root: bool = True, **kwargs: object) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("os.geteuid", return_value=0 if root else 1000):
            code = command.main(
                list(argv),
                stream_out=out,
                stream_err=err,
                policy_path=self.policy,
                **kwargs,  # type: ignore[arg-type]
            )
        return code, out.getvalue(), err.getvalue()

    def test_the_terminal_says_the_sentence(self) -> None:
        code, out, _err = self.run_command(NAME, fetch=Webroot(self.webroot), resolve=resolved)
        self.assertEqual(code, 0)
        self.assertEqual(
            out,
            f"Reached: a test file in the webroot came back over http://{NAME}/. "
            "Checked from this manager, not from the internet.\n",
        )

    def test_json_is_the_helpers_document(self) -> None:
        code, out, _err = self.run_command(
            NAME, "--json", fetch=lambda _u, _t: Reply(404, b"", None, ADDRESS), resolve=resolved
        )
        self.assertEqual(code, 0)
        document = assert_contract("haprion-http01-check", out)
        self.assertEqual(document["result"]["answer"], "other")

    def test_without_root_nothing_is_written(self) -> None:
        fetch = Webroot(self.webroot)
        code, out, err = self.run_command(NAME, root=False, fetch=fetch, resolve=resolved)
        self.assertEqual(code, exit_codes.NOT_ROOT)
        self.assertEqual(out, "")
        self.assertIn("sudo", err)
        self.assertEqual(fetch.urls, [])

    def test_a_refusal_is_said_on_stderr_or_as_the_document(self) -> None:
        code, out, err = self.run_command("*.example.com")
        self.assertEqual((code, out), (exit_codes.REFUSED, ""))
        self.assertIn("DNS-01", err)
        code, out, _err = self.run_command("*.example.com", "--json")
        self.assertEqual(assert_contract("haprion-http01-check", out)["error"]["code"], "bad_input")


class TheSocketClient(unittest.TestCase):
    def answer(self, document: object) -> mock._patch[mock.MagicMock]:
        return mock.patch.object(helper_socket, "ask", return_value=json.dumps(document))

    def test_the_helpers_answer_is_a_check(self) -> None:
        result = Check(NAME, "silent", ADDRESS, None, "port 80 refused the connection")
        with self.answer({"outcome": "done", "result": result.as_dict()}) as asked:
            self.assertEqual(http01_check_socket.ask(NAME), result)
        sent = asked.call_args.args[0]
        self.assertEqual(sent["operation"], "http01_check")
        self.assertEqual(sent["parameters"], {"name": NAME})
        self.assertEqual(asked.call_args.kwargs["path"], "/run/haprion/http01-check.sock")

    def test_a_refusal_keeps_its_code_and_sentence(self) -> None:
        document = {
            "outcome": "failed",
            "result": None,
            "error": {"code": "bad_input", "message": "not a domain name: 'x'"},
        }
        with self.answer(document), self.assertRaises(CheckError) as caught:
            http01_check_socket.ask("x")
        self.assertEqual(
            (caught.exception.code, str(caught.exception)), ("bad_input", "not a domain name: 'x'")
        )

    def test_a_service_that_cannot_be_asked_is_unavailable(self) -> None:
        for error in (
            helper_socket.HelperUnavailable("not running"),
            helper_socket.HelperBusy("busy"),
            helper_socket.HelperSilent("did not answer"),
        ):
            with (
                self.subTest(error=type(error).__name__),
                mock.patch.object(helper_socket, "ask", side_effect=error),
                self.assertRaises(CheckError) as caught,
            ):
                http01_check_socket.ask(NAME)
            self.assertEqual(caught.exception.code, "unavailable")

    def test_an_answer_that_is_not_one_is_unavailable(self) -> None:
        for raw in (
            "not json",
            json.dumps({"outcome": "done", "result": {"answer": "maybe"}}),
            json.dumps({"outcome": "done", "result": {"answer": "reached", "extra": 1}}),
        ):
            with (
                self.subTest(raw=raw),
                mock.patch.object(helper_socket, "ask", return_value=raw),
                self.assertRaises(CheckError) as caught,
            ):
                http01_check_socket.ask(NAME)
            self.assertEqual(caught.exception.code, "unavailable")


class TheHelperUnit(unittest.TestCase):
    def test_systemd_ends_the_helper_after_the_check_and_before_the_web_stops_waiting(self) -> None:
        unit = (
            Path(__file__).resolve().parents[1]
            / "install/platform/examples/haprion-http01-check-helper@.service.example"
        ).read_text()
        self.assertIn("Type=exec", unit)
        seconds = int(unit.split("\nRuntimeMaxSec=", 1)[1].split("\n", 1)[0])
        self.assertLess(seconds, http01_check_socket.TIMEOUT_SECONDS)
        self.assertGreater(seconds, http01_check.TOTAL_SECONDS + http01_check.CONNECT_SECONDS)


if __name__ == "__main__":
    unittest.main()
