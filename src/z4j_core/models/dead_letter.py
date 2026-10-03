"""Dead-letter listing: the ``dlq.list`` command, its models, and its bounds.

A dead letter is a task the engine has given up on and parked: an RQ job in
the ``FailedJobRegistry``, a Dramatiq message in the broker's ``<queue>.XQ``
dead-letter queue. The brain can already resurrect one by id with
``requeue_dead_letter``; this module gives it the read side, so a dashboard
can show *what* is parked before an operator decides to requeue it.

Wire contract
-------------

The brain dispatches a ``command`` frame whose payload is::

    {
        "action": "dlq.list",
        "target": {
            "type": "queue",
            "id": "<queue name or empty>",
            "engine": "<engine>",
        },
        "parameters": {
            "queue": "<name> | null",
            "limit": 100,
            "cursor": "<opaque> | null",
        },
    }

- ``parameters.queue`` (optional, falls back to ``target.queue`` then
  ``target.id``): restrict the page to one queue. Absent or ``null`` lists
  every queue the adapter knows about.
- ``parameters.limit`` (optional, default :data:`DLQ_LIST_DEFAULT_LIMIT`):
  page size. The agent dispatcher clamps anything larger than
  :data:`DLQ_LIST_MAX_LIMIT` down to it and refuses a non-integer or
  non-positive value with ``status="failed"``.
- ``parameters.cursor`` (optional): the ``next_cursor`` of the previous page,
  passed back verbatim. The brain never parses it; its shape belongs to the
  adapter. The two shipping adapters use a decimal offset, see
  :func:`encode_offset_cursor`.

The agent answers with a ``command_result`` frame::

    {"status": "success", "result": <DeadLetterPage.model_dump(mode="json")>}

so ``result`` is exactly::

    {
        "entries": [
            {
                "task_id": "...",
                "task_name": "...",
                "queue": "...",
                "failed_at": "2026-10-02T12:00:00Z" | null,
                "error_excerpt": "...",
                "attempts": 3 | null,
            },
            ...,
        ],
        "next_cursor": "..." | null,
        "total": 12 | null,
        "engine": "rq",
    }

A refusal (capability not advertised, broker unreachable, bad parameters) is
``{"status": "failed", "error": "<reason>", "result": null}``.

The brain stores ``result`` verbatim and re-validates it with
``DeadLetterPage.model_validate_json(...)`` (or ``model_validate(result,
strict=False)``; the domain models are strict, so the ISO ``failed_at``
string only parses in JSON mode).

Capability
----------

An adapter that implements ``QueueEngineAdapter.list_dead_letters`` advertises
:data:`LIST_DEAD_LETTERS_CAPABILITY` (``"list_dead_letters"``) from
``capabilities()``. The agent dispatcher refuses ``dlq.list`` with
``status="failed"`` when the target adapter does not advertise it, before
touching the adapter. Adapters whose engine has no dead-letter store (Celery,
Huey, arq, taskiq) do not advertise it and their ``list_dead_letters`` raises
:class:`z4j_core.errors.AdapterError`.

Size bound
----------

A page carries at most :data:`DLQ_LIST_MAX_LIMIT` entries and every string
field is length-capped, so the largest possible page serialises to roughly
250 KiB, a comfortable margin under the 1 MiB wire-frame cap that the
``command_result`` frame must stay under.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from z4j_core.models._base import Z4JModel
from z4j_core.redaction.engine import RedactionEngine

#: Command action the brain dispatches to list dead letters.
DLQ_LIST_ACTION = "dlq.list"

#: Capability token an adapter advertises when it implements
#: ``list_dead_letters``. Deliberately distinct from the action name: tokens
#: name adapter methods, actions name wire commands.
LIST_DEAD_LETTERS_CAPABILITY = "list_dead_letters"

#: Page size used when the command carries no ``limit``.
DLQ_LIST_DEFAULT_LIMIT = 100

#: Hard ceiling on entries per page. The dispatcher clamps larger requests;
#: the model refuses larger pages outright.
DLQ_LIST_MAX_LIMIT = 200

#: Maximum length of :attr:`DeadLetterEntry.error_excerpt` in characters.
DEAD_LETTER_EXCERPT_MAX_CHARS = 512


class DeadLetterEntry(Z4JModel):
    """One parked task as the engine's dead-letter store describes it.

    Attributes:
        task_id: Engine-native id, the same id ``requeue_dead_letter`` takes.
        task_name: Dotted task / actor name. Empty when the engine does not
                   store the name in a form the adapter can read without
                   deserialising an untrusted payload (the adapter never
                   unpickles broker data to fill this in).
        queue: The queue the task was dead-lettered from, which is where a
               requeue would put it back.
        failed_at: When the engine parked it, UTC. ``None`` when the engine
                   does not record that time.
        error_excerpt: The tail of the stored failure text (traceback or
                       exception string), passed through the redaction engine,
                       at most :data:`DEAD_LETTER_EXCERPT_MAX_CHARS`
                       characters. Empty when nothing was stored.
        attempts: Number of executions the engine recorded before giving up.
                  ``None`` when the engine does not track it.
    """

    task_id: str = Field(min_length=1, max_length=200)
    task_name: str = Field(default="", max_length=500)
    queue: str = Field(min_length=1, max_length=200)
    failed_at: datetime | None = None
    error_excerpt: str = Field(default="", max_length=DEAD_LETTER_EXCERPT_MAX_CHARS)
    attempts: int | None = Field(default=None, ge=0)


class DeadLetterPage(Z4JModel):
    """One page of dead letters, newest first.

    Attributes:
        entries: At most :data:`DLQ_LIST_MAX_LIMIT` entries, newest first
                 (as far as the engine's store orders them).
        next_cursor: Opaque token for the next page, or ``None`` on the last
                     page. The brain passes it back verbatim.
        total: Number of dead letters matching the request across all pages
               when the engine can count cheaply, else ``None``.
        engine: Adapter name that produced the page (``"rq"``,
                ``"dramatiq"``, ...).
    """

    entries: list[DeadLetterEntry] = Field(default_factory=list, max_length=DLQ_LIST_MAX_LIMIT)
    next_cursor: str | None = Field(default=None, max_length=200)
    total: int | None = Field(default=None, ge=0)
    engine: str = Field(min_length=1, max_length=40)


def redact_error_excerpt(text: object, redaction: RedactionEngine) -> str:
    """Turn an engine's stored failure text into a bounded, redacted excerpt.

    Keeps the *tail* of the text, because that is where a traceback carries the
    exception type and message, then runs it through ``redaction`` so a secret
    echoed into an error message never leaves the agent. The result is never
    longer than :data:`DEAD_LETTER_EXCERPT_MAX_CHARS`.
    """
    if text is None:
        return ""
    raw = text if isinstance(text, str) else str(text)
    raw = raw.strip()
    if not raw:
        return ""
    tail = raw[-DEAD_LETTER_EXCERPT_MAX_CHARS:]
    scrubbed = redaction.scrub(tail)
    result = scrubbed if isinstance(scrubbed, str) else str(scrubbed)
    return result[-DEAD_LETTER_EXCERPT_MAX_CHARS:].strip()


def encode_offset_cursor(offset: int) -> str:
    """Encode a page offset as the cursor string the shipping adapters use."""
    return str(int(offset))


def decode_offset_cursor(cursor: str | None) -> int:
    """Decode a cursor produced by :func:`encode_offset_cursor`.

    ``None`` or empty means the first page. Anything that is not a
    non-negative decimal integer raises ``ValueError``; adapters turn that
    into a failed command rather than guessing a page.
    """
    if cursor is None or cursor == "":
        return 0
    if not cursor.isdigit():
        raise ValueError(f"invalid dead-letter cursor {cursor!r}")
    return int(cursor)


__all__ = [
    "DEAD_LETTER_EXCERPT_MAX_CHARS",
    "DLQ_LIST_ACTION",
    "DLQ_LIST_DEFAULT_LIMIT",
    "DLQ_LIST_MAX_LIMIT",
    "LIST_DEAD_LETTERS_CAPABILITY",
    "DeadLetterEntry",
    "DeadLetterPage",
    "decode_offset_cursor",
    "encode_offset_cursor",
    "redact_error_excerpt",
]
