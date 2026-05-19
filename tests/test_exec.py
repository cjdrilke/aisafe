"""Tests for `aisafe exec` subprocess injection."""
from __future__ import annotations

import os
import sys

from aisafe import exec_runner, store


def test_exec_injects_env_into_child(isolated, tmp_path):
    store.set("database.password", "s3cret")
    store.set("database.host", "localhost")

    # Child process prints its env back; we capture via a file.
    out = tmp_path / "out.txt"
    script = tmp_path / "child.py"
    script.write_text(
        "import os, sys\n"
        "with open(sys.argv[1], 'w') as f:\n"
        "    f.write(os.environ.get('DATABASE_PASSWORD','') + '|' + os.environ.get('DATABASE_HOST',''))\n"
    )

    rc = exec_runner.run(
        [sys.executable, str(script), str(out)],
        sections=["database"],
    )
    assert rc == 0
    assert out.read_text() == "s3cret|localhost"


def test_exec_does_not_pollute_parent_env(isolated, tmp_path):
    store.set("api.token", "t0k3n")
    script = tmp_path / "child.py"
    script.write_text("import os; print(os.environ.get('API_TOKEN'))\n")

    assert "API_TOKEN" not in os.environ
    exec_runner.run([sys.executable, str(script)], sections=["api"])
    assert "API_TOKEN" not in os.environ  # parent env unchanged


def test_exec_with_prefix(isolated, tmp_path):
    store.set("api.token", "abc")
    out = tmp_path / "o.txt"
    script = tmp_path / "c.py"
    script.write_text(
        "import os, sys\nwith open(sys.argv[1],'w') as f: f.write(os.environ.get('APP_API_TOKEN',''))\n"
    )
    rc = exec_runner.run(
        [sys.executable, str(script), str(out)],
        sections=["api"],
        prefix="APP_",
    )
    assert rc == 0
    assert out.read_text() == "abc"


def test_exec_individual_keys(isolated, tmp_path):
    store.set("a.b", "v1")
    store.set("a.c", "v2")
    out = tmp_path / "o.txt"
    script = tmp_path / "c.py"
    script.write_text(
        "import os, sys\nwith open(sys.argv[1],'w') as f: f.write(repr(sorted(k for k in os.environ if k.startswith('A_'))))\n"
    )
    exec_runner.run([sys.executable, str(script), str(out)], keys=["a.b"])
    txt = out.read_text()
    assert "A_B" in txt
    assert "A_C" not in txt  # only a.b was exposed


def test_env_export_returns_shell_exports(isolated):
    store.set("api.token", "secret with spaces")
    text = exec_runner.env_export(sections=["api"])
    assert text.startswith("export API_TOKEN=")
    # value should be shell-quoted
    assert "'secret with spaces'" in text


def test_exec_ai_caller_still_gets_creds(isolated, mark_as_ai, tmp_path):
    """exec is the sanctioned escape hatch — AI calling it still works,
    but the AI never sees the values, only the child does. And it's audited."""
    import os
    os.environ.pop("AISAFE_AI")
    store.set("db.pass", "secret")
    os.environ["AISAFE_AI"] = "test-agent"

    out = tmp_path / "o.txt"
    script = tmp_path / "c.py"
    script.write_text(
        "import os, sys\nwith open(sys.argv[1],'w') as f: f.write(os.environ.get('DB_PASS',''))\n"
    )
    rc = exec_runner.run([sys.executable, str(script), str(out)], sections=["db"])
    assert rc == 0
    assert out.read_text() == "secret"

    # And the audit log should record the exec event with exposed names but not values
    audit_path = isolated["audit"]
    text = audit_path.read_text()
    assert "DB_PASS" in text
    assert "secret" not in text  # value not logged
