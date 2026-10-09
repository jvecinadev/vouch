def context_window(text: str, line: int, radius: int):
    """Return (start, end, snippet) with 1-based inclusive line numbers around `line`."""
    lines = text.splitlines()
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    return start, end, "\n".join(lines[start - 1:end])
