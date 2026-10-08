"""Overlapping windows so long documents are scored in full and a payload split across a boundary
still lands whole inside one window. Oversized input raises instead of being silently truncated:
truncation is an evasion route (pad the front, hide the payload at the end)."""


class ClassifierTooLarge(ValueError):
    pass


def _check(n_chunks: int, max_chunks: int) -> None:
    if n_chunks > max_chunks:
        raise ClassifierTooLarge(f"needs {n_chunks} chunks, limit is {max_chunks}")


def char_windows(text: str, size: int, overlap: int, max_chunks: int) -> list[str]:
    if len(text) <= size:
        return [text]
    starts = list(range(0, len(text) - overlap, size - overlap))
    _check(len(starts), max_chunks)
    return [text[s:s + size] for s in starts]


def token_windows(text: str, tokenizer, size: int, overlap: int, max_chunks: int) -> list[str]:
    """Windows of at most `size` tokens, returned as text slices (via tokenizer offsets)."""
    try:
        offs = tokenizer(text, add_special_tokens=False, return_offsets_mapping=True)["offset_mapping"]
    except (NotImplementedError, KeyError, TypeError) as e:
        raise RuntimeError("Prompt Guard needs a fast tokenizer (offset mapping)") from e
    n = len(offs)
    if n <= size:
        return [text]
    starts = list(range(0, n - overlap, size - overlap))
    _check(len(starts), max_chunks)
    return [text[offs[s][0]:offs[min(s + size, n) - 1][1]] for s in starts]
