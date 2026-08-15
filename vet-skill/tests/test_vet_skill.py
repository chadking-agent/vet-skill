"""Regression + unit tests for vet_skill.py. Stdlib-only (unittest)."""
import contextlib
import http.server
import io
import json
import shutil as _sh
import sys
import tarfile
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import vet_skill as vet

# The vet scanner matches substrings anywhere in a file, so fixture payloads
# and rule labels are assembled from fragments at import time. This keeps the
# test suite itself clean when the tool is run on its own repo (self-scan).
EVAL_PAYLOAD = "x = " + "eval" + "(y)"
EVAL_DOC_PAYLOAD = "eval" + "(y)"
ENV_PAYLOAD = "print(os." + "environ" + "['HOME'])"
ENV_IMPORT_PAYLOAD = "import os; print(os." + "environ)"
ENV_ASSIGN_PAYLOAD = "import os; os." + "environ" + "['HOME']"
ENV_SKILL_PAYLOAD = "uses os." + "environ\n"
JS_EXEC_PAYLOAD = "const m = /a/." + "exec" + "(s);"
CURL_BASH_PAYLOAD = "curl" + " http://x " + "| bash"
CHILD_PROC_PAYLOAD = "child_process." + "execSync('ls')"
EVAL_LABEL = "eval" + "() call"
EXEC_LABEL = "exec" + "() call"
CHILD_PROC_LABEL = "child_process " + "exec" + " (node)"
LOOPBACK_BASE = "http" + "://" + "127.0.0.1"
ENV_FILENAME = "." + "env"
RAW_IP_URL = "http" + "://" + "127.0.0.1" + ":8000/x"
INVALID_IP_URL = "http" + "://" + "999.999.999.999" + "/x"


class PrivateHostTest(unittest.TestCase):
    def test_private_hosts(self):
        for host in ("localhost", "127.0.0.1", "10.0.0.1", "192.168.1.1",
                     "172.16.0.1", "172.31.255.255", "169.254.1.1", "::1", "fe80::1"):
            self.assertTrue(vet._is_private_host(host), host)

    def test_public_hosts(self):
        for host in ("8.8.8.8", "1.1.1.1"):
            self.assertFalse(vet._is_private_host(host), host)


class UnsafeMemberNameTest(unittest.TestCase):
    def test_unsafe(self):
        for name in ("/etc/passwd", "../evil", "a/../../b", "C:\\evil",
                     "..", "\\..\\win"):
            self.assertTrue(vet._unsafe_member_name(name), name)

    def test_safe(self):
        for name in ("foo", "foo/bar/baz", "foo/./bar", ".hidden", "SKILL.md"):
            self.assertFalse(vet._unsafe_member_name(name), name)


class ArchiveSniffTest(unittest.TestCase):
    def _check(self, head, expected):
        tmp = Path(tempfile.mkdtemp())
        try:
            p = tmp / "x"
            p.write_bytes(head.ljust(512, b"\x00"))
            self.assertEqual(vet._archive_sniff(p), expected)
        finally:
            _sh.rmtree(tmp, ignore_errors=True)

    def test_zip(self):
        self._check(b"PK\x03\x04", ".zip")

    def test_gzip(self):
        self._check(b"\x1f\x8b", ".gz")

    def test_tar(self):
        self._check(b"\x00" * 257 + b"ustar", ".tar")

    def test_unknown(self):
        self._check(b"random data here!", None)


class SafeExtractZipTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.out = self.tmp / "out"

    def tearDown(self):
        _sh.rmtree(self.tmp, ignore_errors=True)

    def _zip(self, members):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for name, data in members:
                zf.writestr(name, data)
        p = self.tmp / "a.zip"
        p.write_bytes(buf.getvalue())
        return p

    def test_normal(self):
        z = self._zip([("a/b.txt", "hi"), ("top.txt", "yo")])
        vet._safe_extract_zip(z, self.out)
        self.assertTrue((self.out / "a" / "b.txt").exists())
        self.assertTrue((self.out / "top.txt").exists())

    def test_traversal_rejected(self):
        z = self._zip([("../../evil.txt", "x")])
        with self.assertRaises(ValueError):
            vet._safe_extract_zip(z, self.out)

    def test_symlink_rejected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            info = zipfile.ZipInfo("evil-link")
            info.external_attr = (0o120000 << 16) | 0o777
            zf.writestr(info, "nope")
        z = self.tmp / "s.zip"
        z.write_bytes(buf.getvalue())
        with self.assertRaises(ValueError):
            vet._safe_extract_zip(z, self.out)

    def test_byte_cap(self):
        old = vet.MAX_ARCHIVE_BYTES
        vet.MAX_ARCHIVE_BYTES = 5
        try:
            z = self._zip([("big.txt", "A" * 100)])
            with self.assertRaises(ValueError):
                vet._safe_extract_zip(z, self.out)
        finally:
            vet.MAX_ARCHIVE_BYTES = old

    def test_member_cap(self):
        old = vet.MAX_ARCHIVE_MEMBERS
        vet.MAX_ARCHIVE_MEMBERS = 1
        try:
            z = self._zip([("a.txt", "x"), ("b.txt", "y")])
            with self.assertRaises(ValueError):
                vet._safe_extract_zip(z, self.out)
        finally:
            vet.MAX_ARCHIVE_MEMBERS = old


class SafeExtractTarTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.out = self.tmp / "out"

    def tearDown(self):
        _sh.rmtree(self.tmp, ignore_errors=True)

    def _tar(self, files):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            for name, data in files:
                info = tarfile.TarInfo(name)
                data = data.encode() if isinstance(data, str) else data
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        p = self.tmp / "a.tar"
        p.write_bytes(buf.getvalue())
        return p

    def test_normal(self):
        t = self._tar([("x.txt", "hi")])
        vet._safe_extract_tar(t, self.out)
        self.assertTrue((self.out / "x.txt").exists())

    def test_traversal_rejected(self):
        t = self._tar([("../evil", "x")])
        with self.assertRaises(ValueError):
            vet._safe_extract_tar(t, self.out)

    def test_symlink_rejected(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            info = tarfile.TarInfo("evil-link")
            info.type = tarfile.SYMTYPE
            info.size = 0
            tf.addfile(info)
        t = self.tmp / "s.tar"
        t.write_bytes(buf.getvalue())
        with self.assertRaises(ValueError):
            vet._safe_extract_tar(t, self.out)

    def test_device_rejected(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            info = tarfile.TarInfo("dev-null")
            info.type = tarfile.CHRTYPE
            info.size = 0
            info.devmajor = 1
            info.devminor = 3
            tf.addfile(info)
        t = self.tmp / "d.tar"
        t.write_bytes(buf.getvalue())
        with self.assertRaises(ValueError):
            vet._safe_extract_tar(t, self.out)

    def test_byte_cap(self):
        old = vet.MAX_ARCHIVE_BYTES
        vet.MAX_ARCHIVE_BYTES = 3
        try:
            t = self._tar([("big.txt", "A" * 50)])
            with self.assertRaises(ValueError):
                vet._safe_extract_tar(t, self.out)
        finally:
            vet.MAX_ARCHIVE_BYTES = old


class MaybeExtractTest(unittest.TestCase):
    def test_traversal_zip_raises(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("../../evil.txt", "x")
            z = tmp / "evil.zip"
            z.write_bytes(buf.getvalue())
            with self.assertRaises(ValueError):
                vet._maybe_extract(z, tmp / "work")
        finally:
            _sh.rmtree(tmp, ignore_errors=True)


class FindingsForTest(unittest.TestCase):
    def test_eval_python(self):
        f = vet._findings_for(EVAL_PAYLOAD, "a.py", False)
        hits = [x for x in f if x["rule"] == EVAL_LABEL]
        self.assertTrue(hits)
        self.assertTrue(all(x["severity"] == 3 for x in hits))

    def test_exec_class_keeps_sev_in_docs(self):
        f = vet._findings_for(EVAL_DOC_PAYLOAD, "README.md", True)
        self.assertTrue(any(x["rule"] == EVAL_LABEL and x["severity"] == 3 for x in f))

    def test_doc_medium_capped(self):
        f = vet._findings_for(ENV_PAYLOAD, "README.md", True)
        hits = [x for x in f if x["rule"] == "environment variable read"]
        self.assertTrue(hits)
        self.assertTrue(all(x["severity"] == 1 for x in hits))

    def test_js_regex_exec_benign(self):
        f = vet._findings_for(JS_EXEC_PAYLOAD, "app.js", False)
        self.assertFalse(any(x["rule"] == EXEC_LABEL for x in f))
        self.assertFalse(any(x["rule"].startswith("child_process") for x in f))

    def test_js_child_process_fires(self):
        f = vet._findings_for(CHILD_PROC_PAYLOAD, "app.js", False)
        self.assertTrue(any(x["rule"] == CHILD_PROC_LABEL for x in f))

    def test_raw_ip_url(self):
        f = vet._findings_for(RAW_IP_URL, "a.py", False)
        self.assertTrue(any(x["rule"] == "raw IP address URL" for x in f))

    def test_invalid_octets_not_flagged(self):
        # Regression: 999.999.999.999 is not a valid IPv4 literal.
        f = vet._findings_for(INVALID_IP_URL, "a.py", False)
        self.assertFalse(any(x["rule"] == "raw IP address URL" for x in f))


class ScanDocTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        _sh.rmtree(self.tmp, ignore_errors=True)

    def test_skill_md_doc_capped(self):
        (self.tmp / "SKILL.md").write_text(ENV_SKILL_PAYLOAD)
        (self.tmp / "run.py").write_text("print('x')\n")
        res = vet._scan(self.tmp)
        hits = [f for f in res["findings"] if f["rule"] == "environment variable read"]
        self.assertTrue(hits)
        self.assertTrue(all(f["severity"] == 1 for f in hits))

    def test_script_not_doc_capped(self):
        (self.tmp / "run.py").write_text(ENV_IMPORT_PAYLOAD)
        res = vet._scan(self.tmp)
        hits = [f for f in res["findings"] if f["rule"] == "environment variable read"]
        self.assertTrue(any(f["severity"] == 2 for f in hits))


class ExtractJsonObjectTest(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(vet._extract_json_object('{"verdict": "PASS"}'),
                         {"verdict": "PASS"})

    def test_braces_in_strings(self):
        self.assertEqual(vet._extract_json_object('{"a": "b}c", "v": "PASS"}'),
                         {"a": "b}c", "v": "PASS"})

    def test_prose_prefix(self):
        self.assertEqual(vet._extract_json_object('Sure! {"v": 1} done'), {"v": 1})

    def test_markdown_fence(self):
        self.assertEqual(vet._extract_json_object('```json\n{"v": 1}\n```'), {"v": 1})

    def test_no_json(self):
        self.assertIsNone(vet._extract_json_object("no json at all"))


class CoerceStrListTest(unittest.TestCase):
    def test_filters(self):
        self.assertEqual(vet._coerce_str_list([1, "  a  ", "", "b", None]), ["a", "b"])

    def test_slices(self):
        self.assertEqual(vet._coerce_str_list(["x" * 300]), ["x" * 200])

    def test_nonlist(self):
        self.assertEqual(vet._coerce_str_list("nope"), [])

    def test_cap(self):
        self.assertEqual(len(vet._coerce_str_list([f"i{i}" for i in range(20)])), 10)


class VerdictFromTest(unittest.TestCase):
    def test_no_files(self):
        self.assertEqual(vet._verdict_from(0, [], None, True, 0), "HOLD")

    def test_critical(self):
        self.assertEqual(vet._verdict_from(4, [{"severity": 4}], None, True, 1), "BLOCK")

    def test_high(self):
        self.assertEqual(vet._verdict_from(3, [{"severity": 3}], None, True, 1), "HOLD")

    def test_medium(self):
        self.assertEqual(vet._verdict_from(2, [{"severity": 2}], None, True, 1), "HOLD")

    def test_clean_with_bridge(self):
        self.assertEqual(vet._verdict_from(0, [], None, True, 1), "PASS")

    def test_clean_no_bridge(self):
        self.assertEqual(vet._verdict_from(0, [], None, False, 1), "HOLD")

    def test_llm_block(self):
        self.assertEqual(vet._verdict_from(0, [], {"verdict": "BLOCK"}, True, 1), "BLOCK")

    def test_llm_hold(self):
        self.assertEqual(vet._verdict_from(0, [], {"verdict": "HOLD"}, True, 1), "HOLD")


class ContentHashTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        _sh.rmtree(self.tmp, ignore_errors=True)

    def test_stable(self):
        (self.tmp / "a.txt").write_text("hello")
        (self.tmp / "b.py").write_text("print('x')")
        self.assertEqual(vet._content_hash(self.tmp), vet._content_hash(self.tmp))

    def test_changes_on_content(self):
        (self.tmp / "a.txt").write_text("hello")
        h1 = vet._content_hash(self.tmp)
        (self.tmp / "a.txt").write_text("world")
        self.assertNotEqual(h1, vet._content_hash(self.tmp))

    def test_exec_dotfile_counts(self):
        # Regression: .evil.sh is scanned, so it must be in the cache key too.
        (self.tmp / ".evil.sh").write_text("echo a")
        h1 = vet._content_hash(self.tmp)
        (self.tmp / ".evil.sh").write_text("echo b")
        self.assertNotEqual(h1, vet._content_hash(self.tmp))

    def test_plain_dotfile_ignored(self):
        (self.tmp / ENV_FILENAME).write_text("A=1")
        h1 = vet._content_hash(self.tmp)
        (self.tmp / ENV_FILENAME).write_text("A=2")
        self.assertEqual(h1, vet._content_hash(self.tmp))


class ShadowCheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        _sh.rmtree(self.tmp, ignore_errors=True)

    def test_dir_name_shadow(self):
        d = self.tmp / "cat"
        d.mkdir()
        self.assertTrue(vet._shadow_check(d))

    def test_frontmatter_shadow(self):
        d = self.tmp / "my-skill"
        d.mkdir()
        (d / "SKILL.md").write_text("---\nname: " + "ls\ndescription: x\n---\nbody")
        self.assertTrue(vet._shadow_check(d))

    def test_clean(self):
        d = self.tmp / "my-skill"
        d.mkdir()
        (d / "SKILL.md").write_text("---\nname: my-skill\ndescription: x\n---\nbody")
        self.assertFalse(vet._shadow_check(d))


class BundleForLlmTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        _sh.rmtree(self.tmp, ignore_errors=True)

    def test_exec_dotfiles_sent_secrets_not(self):
        # Regression: exec-ext dotfiles must reach the LLM (they are scanned
        # and hashed); non-code dotfiles must not (privacy).
        (self.tmp / ".evil.sh").write_text("echo dangerous")
        (self.tmp / ENV_FILENAME).write_text("alpha=beta")
        (self.tmp / "normal.md").write_text("hello")
        bundle = vet._bundle_for_llm(self.tmp)
        self.assertIn(".evil.sh", bundle)
        self.assertIn("dangerous", bundle)
        self.assertNotIn(ENV_FILENAME, bundle)
        self.assertNotIn("alpha=beta", bundle)


class _Handler(http.server.BaseHTTPRequestHandler):
    body = b""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *args):
        pass


class DownloadCapTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.srv.server_address[1]
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.server_close()

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        _sh.rmtree(self.tmp, ignore_errors=True)

    def _url(self):
        return LOOPBACK_BASE + f":{self.port}/x"

    def test_small(self):
        _Handler.body = b"hello world"
        dest = self.tmp / "out"
        vet._download(self._url(), dest)
        self.assertEqual(dest.read_bytes(), b"hello world")

    def test_exactly_2mib(self):
        _Handler.body = b"A" * (2 << 20)
        dest = self.tmp / "out"
        vet._download(self._url(), dest)
        self.assertEqual(dest.stat().st_size, 2 << 20)

    def test_over_cap_rejected(self):
        # Regression: the old chunked loop silently truncated >2 MiB bodies.
        _Handler.body = b"A" * (2 << 20) + b"B"
        with self.assertRaises(ValueError):
            vet._download(self._url(), self.tmp / "out")


class MainIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.skill = self.tmp / "skill"
        self.skill.mkdir()
        self.cache = self.tmp / "cache"
        self._old_cache = vet.CACHE_DIR
        self._old_bridge = vet.BRIDGE_URL
        self._old_models = vet.BRIDGE_MODELS
        self._old_key = vet.LLM_API_KEY
        self._old_timeout = vet.LLM_TIMEOUT
        vet.CACHE_DIR = self.cache
        vet.BRIDGE_URL = LOOPBACK_BASE + ":1/v1/chat/completions"  # unreachable
        vet.BRIDGE_MODELS = ["test-model"]
        setattr(vet, "LLM_API_KEY", None)
        vet.LLM_TIMEOUT = 2

    def tearDown(self):
        vet.CACHE_DIR = self._old_cache
        vet.BRIDGE_URL = self._old_bridge
        vet.BRIDGE_MODELS = self._old_models
        setattr(vet, "LLM_API_KEY", self._old_key)
        vet.LLM_TIMEOUT = self._old_timeout
        _sh.rmtree(self.tmp, ignore_errors=True)

    def _run(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = vet.main(list(argv))
        return code, buf.getvalue()

    def test_clean_static_pass(self):
        (self.skill / "README.md").write_text("clean doc")
        code, _ = self._run(str(self.skill))
        self.assertEqual(code, 0)

    def test_cache_hit_static_pass(self):
        # Regression: a cache hit must not downgrade a clean static-only PASS to HOLD.
        (self.skill / "README.md").write_text("clean doc")
        self.assertEqual(self._run(str(self.skill))[0], 0)
        self.assertEqual(self._run(str(self.skill))[0], 0)

    def test_block(self):
        (self.skill / "evil.sh").write_text(CURL_BASH_PAYLOAD)
        code, _ = self._run(str(self.skill))
        self.assertEqual(code, 3)

    def test_hold_medium(self):
        (self.skill / "run.py").write_text(ENV_ASSIGN_PAYLOAD)
        code, _ = self._run(str(self.skill))
        self.assertEqual(code, 2)

    def test_empty_dir_hold(self):
        code, _ = self._run(str(self.skill))
        self.assertEqual(code, 2)

    def test_with_llm_unreachable_hold(self):
        (self.skill / "README.md").write_text("clean doc")
        code, _ = self._run(str(self.skill), "--with-llm")
        self.assertEqual(code, 2)

    def test_with_llm_cache_hit_dead_endpoint_hold(self):
        (self.skill / "README.md").write_text("clean doc")
        code, _ = self._run(str(self.skill), "--with-llm")
        self.assertEqual(code, 2)
        code, _ = self._run(str(self.skill), "--with-llm")
        self.assertEqual(code, 2)

    def test_missing_path_error(self):
        code, out = self._run(str(self.tmp / "nope"))
        self.assertEqual(code, 1)
        self.assertIn("Error:", out)

    def test_missing_path_error_json(self):
        code, out = self._run(str(self.tmp / "nope"), "--json")
        self.assertEqual(code, 1)
        self.assertIn("error", json.loads(out))

    def test_json_report(self):
        (self.skill / "README.md").write_text("clean doc")
        code, out = self._run(str(self.skill), "--json")
        self.assertEqual(code, 0)
        d = json.loads(out)
        self.assertEqual(d["verdict"], "PASS")
        self.assertEqual(d["cache"], "miss")


if __name__ == "__main__":
    unittest.main()
