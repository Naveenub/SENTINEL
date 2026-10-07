import html
import re

from sentinel.models import Item

_CLOSE = re.compile(r"<\s*/\s*untrusted", re.I)


def tag(item: Item) -> str:
    """Wrap external content so the model can be told: everything inside is data, not instructions."""
    if item.source == "user":
        return item.text
    body = _CLOSE.sub("<\\/untrusted", item.text)  # content must not be able to close the wrapper
    return f'<untrusted source="{html.escape(item.ref, quote=True)}">\n{body}\n</untrusted>'
