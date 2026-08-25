"""One redactor, and every place that shows a broker URL uses it.

A broker URL carries a password and routinely ends up in a log line, an error
message or a pasted traceback. The scheduler's rq importer had a private
redactor; the rq worker bootstrap, in a package that could not import it, logged
the same URL verbatim from inside the user's own worker process. Two homes for
one rule, and only one of them applied it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from z4j_core.redaction import redact_url_password

PACKAGES = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("redis://:hunter2@h:6379/0", "redis://:***@h:6379/0"),
        ("redis://user:hunter2@h:6379/0", "redis://user:***@h:6379/0"),
        ("rediss://user:hunter2@h:6380/1", "rediss://user:***@h:6380/1"),
        ("amqp://guest:guest@rabbit:5672//", "amqp://guest:***@rabbit:5672//"),
    ],
)
def test_a_password_never_survives(url: str, expected: str) -> None:
    assert redact_url_password(url) == expected


def test_a_url_with_nothing_to_hide_is_unchanged() -> None:
    """Redaction that mangles harmless URLs gets worked around."""
    assert redact_url_password("redis://h:6379/0") == "redis://h:6379/0"


def test_an_unparseable_url_does_not_raise_into_a_log_call() -> None:
    """This is called from except blocks; raising there loses the real error."""
    assert redact_url_password("://:::") is not None


def test_no_package_renders_a_credential_bearing_url_without_redacting_it() -> None:
    """The class, not the four instances that were found.

    Two corrections are baked in here, both from guards that looked right.

    SCOPE. An earlier version matched any name ending in ``url``, which flagged
    fifteen sites that carry no credential at all: ``brain_url`` in a "use
    https" refusal, ``request.url.path``, the public version-check endpoint.
    Redacting those makes the message useless, and a check that fires on the
    correct usage is one somebody deletes. Only connection strings that
    routinely embed a password are in scope.

    SPELLING. The version before that walked positional arguments only, so the
    idiom this codebase actually logs with, ``logger.error("failed",
    url=dsn)``, was invisible, as were ``self._dsn``, ``%``-formatting,
    ``.format()`` and concatenation. It reported clean while every keyword call
    site in the repository was unexamined.
    """
    import ast

    #: Names that denote a connection string with a password in it. Deliberately
    #: not "anything ending in url": see the docstring.
    credential_bearing = {"redis_url", "broker_url", "database_url", "dsn", "db_url"}
    log_methods = {
        "debug",
        "info",
        "warning",
        "warn",
        "error",
        "exception",
        "critical",
        "log",
    }

    def is_leaky(name: str | None) -> bool:
        if not name:
            return False
        bare = name.lstrip("_")
        return bare in credential_bearing or (
            bare.endswith(("_dsn", "_url"))
            and bare
            not in {
                "brain_url",
                "brain_rest_url",
                "brain_grpc_url",
                "public_url",
                "version_check_url",
                "scheduler_trigger_url",
                "callback_url",
                "webhook_url",
            }
        )

    def already_redacted(node: ast.AST) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                callee = getattr(sub.func, "id", None) or getattr(sub.func, "attr", "")
                if "redact" in (callee or "").lower():
                    return True
        return False

    offenders: list[str] = []
    for path in PACKAGES.rglob("src/**/*.py"):
        if "__pycache__" in path.parts:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            call: ast.Call | None = None
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr in log_methods:
                    call = node
            elif isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
                call = node.exc
            if call is None:
                continue

            # Positional AND keyword, because structlog is keyword-first and
            # that is how nearly every call site in this repository is written.
            rendered = [*call.args, *(kw.value for kw in call.keywords)]
            for expr in rendered:
                if already_redacted(expr):
                    continue
                for sub in ast.walk(expr):
                    name = None
                    if isinstance(sub, ast.Name):
                        name = sub.id
                    elif isinstance(sub, ast.Attribute):
                        name = sub.attr
                    if is_leaky(name):
                        rel = path.relative_to(PACKAGES).as_posix()
                        offenders.append(f"{rel}:{call.lineno}  renders {name}")
                        break

    assert sorted(set(offenders)) == [], (
        "a connection string that routinely carries a password is rendered "
        "into a log line or an exception without redact_url_password:"
        + chr(10)
        + "  "
        + (chr(10) + "  ").join(sorted(set(offenders)))
    )


@pytest.mark.parametrize(
    "malformed",
    [
        "redis://user:secret@host:notaport/0",
        "redis://user:secret@host:99999999999999/0",
        "redis://:@:",
        "://:::",
        "",
        "not a url at all",
    ],
)
def test_a_malformed_url_never_raises(malformed: str) -> None:
    """This is called from except blocks, so raising loses the real error.

    ``urlparse`` does not validate the port; reading ``parsed.port`` on
    ``redis://u:p@host:notaport/0`` raises ValueError. The first version guarded
    only the parse call, so a malformed URL crashed here.

    That was worse than a redaction miss. The rq worker bootstrap is
    deliberately fail-soft: a broker it cannot reach leaves the user's worker
    running without z4j. Raising while formatting that handler's log turned a
    skipped bootstrap into an aborted one, which is a regression against the
    previous release rather than a cosmetic problem.
    """
    assert isinstance(redact_url_password(malformed), str)


def test_a_malformed_url_with_a_password_does_not_pass_it_through() -> None:
    """Failing to parse is not a reason to print the secret."""
    assert "secret" not in redact_url_password("redis://user:secret@host:notaport/0")
