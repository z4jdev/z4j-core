"""Redact credentials from connection URLs before they reach a human.

A broker URL is a connection-string primary: it routinely carries a password,
and it routinely ends up in a log line, an error message, a CI transcript or an
issue-tracker paste. Every place z4j puts one in front of a person has to strip
it first.

This lives in ``z4j-core`` because more than one package needs it and every
package depends on core. The first copy was a private helper in the scheduler's
rq importer, and while it was the only copy the same URL was being logged
verbatim, password included, from the rq worker bootstrap that runs inside the
user's own application. One redactor in one place is the point.
"""

from __future__ import annotations

from urllib.parse import urlparse, urlunparse

__all__ = ["redact_url_password"]

#: What replaces the password. Fixed text, so it cannot itself leak a length.
_MASK = "***"


def redact_url_password(url: str) -> str:
    """Return ``url`` with any password replaced by ``***``.

    Passes the URL through unchanged when it carries no password, so a URL with
    nothing to hide stays readable. Returns a fixed placeholder rather than the
    input when the URL cannot be parsed, because a string that failed parsing is
    exactly the one whose shape should not be assumed.
    """
    # One try around EVERYTHING, because the attribute accesses raise too.
    # urlparse itself is lazy: it does not validate the port, and reading
    # ``parsed.port`` on ``redis://u:p@host:notaport/0`` raises ValueError.
    # The first version guarded only the parse call, so a malformed URL
    # crashed here instead of being redacted.
    #
    # That matters more than a redaction miss. This is called from ``except``
    # blocks while formatting the error already being reported, and one of
    # those callers, the rq worker bootstrap, is deliberately fail-soft: a
    # broker it cannot reach must leave the user's worker running without
    # z4j. Raising from inside that handler turned a skipped bootstrap into
    # an aborted one, a regression against the previous release.
    #
    # The contract is therefore total: a string comes back for any input.
    try:
        parsed = urlparse(url)
        if not parsed.password:
            return url
        host = parsed.hostname or ""
        # ``hostname`` strips the brackets from an IPv6 literal, so putting it
        # back unbracketed produced ``redis://user:***@::1:6379/0``: not a URL
        # anybody can paste back. The redacted string is for a human to read,
        # but a human who copies it should get something valid.
        if ":" in host:
            host = f"[{host}]"
        port = parsed.port
        if port is not None:
            host = f"{host}:{port}"
        user = parsed.username or ""
        return urlunparse(parsed._replace(netloc=f"{user}:{_MASK}@{host}"))
    except Exception:
        # Malformed, and it may still hold a password, so return the
        # placeholder rather than the input.
        return "<unparseable url>"
