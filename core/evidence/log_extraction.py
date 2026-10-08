"""Bounded log extraction (spec Part H): never send unlimited logs to the LLM.

Extracts error regions, the stack trace, N surrounding lines and matching signatures, caps
the excerpt at ``max_bytes`` (UTF-8 safe), and keeps a reference to the original.
"""

import re

from pydantic import BaseModel, Field

from core.evidence.normalizer import signature_patterns

_ERROR_LINE = re.compile(
    r"\b(ERROR|CRITICAL|FATAL|Exception|Error:|Traceback|FAILED|failed)\b", re.IGNORECASE
)
_TRACEBACK_START = re.compile(r"^Traceback \(most recent call last\):")
_JAVA_FRAME = re.compile(r"^\s+at\s+[\w.$]+\(.*\)\s*$")
_TRUNCATION_MARKER = "\n...[truncated]...\n"


class LogExcerpt(BaseModel):
    excerpt: str
    stack_trace: str | None = None
    error_line_numbers: list[int] = Field(default_factory=list)
    matched_signatures: list[str] = Field(default_factory=list)
    original_size_bytes: int
    excerpt_size_bytes: int
    truncated: bool
    original_reference: str | None = None


def _extract_stack_trace(lines: list[str]) -> str | None:
    for i, line in enumerate(lines):
        if _TRACEBACK_START.match(line):
            block = [line]
            for nxt in lines[i + 1 :]:
                block.append(nxt)
                if nxt and not nxt[0].isspace():
                    break
            return "\n".join(block)
    for i, line in enumerate(lines):
        if _JAVA_FRAME.match(line):
            start = max(i - 1, 0)
            end = i
            while end + 1 < len(lines) and _JAVA_FRAME.match(lines[end + 1]):
                end += 1
            return "\n".join(lines[start : end + 1])
    return None


def _truncate_utf8(text: str, max_bytes: int) -> tuple[str, bool]:
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text, False
    budget = max(max_bytes - len(_TRUNCATION_MARKER.encode("utf-8")), 0)
    head = encoded[:budget].decode("utf-8", errors="ignore")
    return head + _TRUNCATION_MARKER, True


def extract_log_excerpt(
    log_text: str,
    *,
    max_bytes: int,
    context_lines: int = 5,
    original_reference: str | None = None,
) -> LogExcerpt:
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    lines = log_text.splitlines()
    signatures = signature_patterns()

    error_idx: list[int] = []
    matched: list[str] = []
    for i, line in enumerate(lines):
        sig_hit = False
        for pattern in signatures:
            found = pattern.search(line)
            if found:
                sig_hit = True
                if found.group(0) not in matched:
                    matched.append(found.group(0))
        if sig_hit or _ERROR_LINE.search(line):
            error_idx.append(i)

    stack_trace = _extract_stack_trace(lines)

    if error_idx:
        keep: set[int] = set()
        for i in error_idx:
            keep.update(range(max(i - context_lines, 0), min(i + context_lines + 1, len(lines))))
        ordered = sorted(keep)
        chunks: list[str] = []
        prev = None
        for i in ordered:
            if prev is not None and i != prev + 1:
                chunks.append("...")
            chunks.append(lines[i])
            prev = i
        region = "\n".join(chunks)
    else:
        region = "\n".join(lines[-(2 * context_lines + 1) :])

    excerpt, truncated = _truncate_utf8(region, max_bytes)
    original_size = len(log_text.encode("utf-8"))
    return LogExcerpt(
        excerpt=excerpt,
        stack_trace=_truncate_utf8(stack_trace, max_bytes)[0] if stack_trace else None,
        error_line_numbers=[i + 1 for i in error_idx],
        matched_signatures=matched,
        original_size_bytes=original_size,
        excerpt_size_bytes=len(excerpt.encode("utf-8")),
        truncated=truncated or len(region.encode("utf-8")) < original_size,
        original_reference=original_reference,
    )
