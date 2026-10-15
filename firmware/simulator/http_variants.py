"""Seeded local-lab request grammars; neither exploit execution nor benchmark reproduction."""
import hashlib
from html import escape
import json
import random
import string
from collections import Counter
from dataclasses import dataclass
from urllib.parse import urlencode

VERSION = "http-grammar-v1"
PATHS = ("/search", "/items", "/profile", "/comments", "/catalog", "/feedback", "/lookup", "/api/search")
PARAMETERS = ("q", "value", "search", "name", "filter", "message", "input", "text")
USER_AGENTS = ("Mozilla/5.0", "AERO-Lab-Client/1.0")
SQL_FAMILIES = ("quoted_boolean", "numeric_boolean", "union_constants", "stacked_select", "exists_constant", "like_expression", "case_expression", "arithmetic_boolean")
XSS_FAMILIES = ("script", "image_event", "svg_event", "focus_event", "toggle_event", "load_event", "javascript_uri", "attribute_context")


@dataclass(frozen=True)
class HttpVariant:
    family: str
    placement: str
    method: str
    uri: str
    body: bytes
    content_type: str | None
    user_agent: str
    variant_id: str

    def wire_request(self, host: str, port: int) -> bytes:
        headers = [f"{self.method} {self.uri} HTTP/1.1", f"Host: {host}:{port}",
                   f"User-Agent: {self.user_agent}", "Accept: */*", "Connection: close"]
        if self.content_type:
            headers.extend([f"Content-Type: {self.content_type}", f"Content-Length: {len(self.body)}"])
        return ("\r\n".join(headers) + "\r\n\r\n").encode("utf-8") + self.body

    def context(self) -> dict[str, str]:
        return {"request_variant_id": self.variant_id, "request_template_family": self.family,
                "request_placement": self.placement, "request_method": self.method,
                "request_generator_version": VERSION}


class HttpVariantGenerator:
    def __init__(self, seed: int) -> None:
        self.seed = seed
        self.rng = random.Random(seed)
        self.generated = 0
        self.families: Counter = Counter()
        self.placements: Counter = Counter()

    def next(self, scenario: str) -> HttpVariant:
        if scenario not in ("SQL_injection", "XSS"):
            raise ValueError("HTTP grammar supports SQL_injection and XSS only")
        r = self.rng
        word = "".join(r.choices(string.ascii_lowercase, k=r.randint(4, 12)))
        number = r.randint(2, 9999)
        quote = r.choice(("'", '"'))
        if scenario == "SQL_injection":
            family = SQL_FAMILIES[self.generated % len(SQL_FAMILIES)]
            projection = ",".join(str(r.randint(1, 9999)) for _ in range(r.randint(2, 6)))
            fragments = {
                "quoted_boolean": f"{word}{quote} OR {quote}{word}{quote}={quote}{word}{quote} -- ",
                "numeric_boolean": f"{number} OR {number}={number} -- ",
                "union_constants": f"{word}{quote} UNION SELECT {projection} -- ",
                "stacked_select": f"{word}{quote}; SELECT {number}; -- ",
                "exists_constant": f"{word}{quote} OR EXISTS (SELECT {number}) -- ",
                "like_expression": f"{word}{quote} OR {quote}{word}{quote} LIKE {quote}{word[:2]}%{quote} -- ",
                "case_expression": f"{number} OR CASE WHEN {number}={number} THEN 1 ELSE 0 END=1 -- ",
                "arithmetic_boolean": f"{number} OR ({number}+1)>{number} -- ",
            }
            payload = fragments[family]
        else:
            family = XSS_FAMILIES[self.generated % len(XSS_FAMILIES)]
            action = f"alert({quote}{word}{number}{quote})"
            attribute_action = escape(action, quote=True)
            fragments = {
                "script": f"<script>{action}</script>",
                "image_event": f'<img src="/missing/{word}" onerror="{attribute_action}">',
                "svg_event": f'<svg onload="{attribute_action}"></svg>',
                "focus_event": f'<input value="{word}" onfocus="{attribute_action}" autofocus>',
                "toggle_event": f'<details open ontoggle="{attribute_action}"><summary>{word}</summary></details>',
                "load_event": f'<body onload="{attribute_action}">{word}</body>',
                "javascript_uri": f"javascript:{action}",
                "attribute_context": f'{quote}><span onmouseover="{attribute_action}">{word}</span>',
            }
            payload = fragments[family]
        placement = r.choice(("query", "form", "json"))
        parameter = r.choice(PARAMETERS)
        path = r.choice(PATHS)
        values = {parameter: payload, "page": str(r.randint(1, 50))}
        if placement == "query":
            method, uri, body, content_type = "GET", path + "?" + urlencode(values), b"", None
        elif placement == "form":
            method, uri, body, content_type = "POST", path, urlencode(values).encode(), "application/x-www-form-urlencoded"
        else:
            method, uri = "POST", path
            body = json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode()
            content_type = "application/json"
        variant_id = hashlib.sha256(uri.encode() + b"\x00" + body).hexdigest()[:24]
        self.generated += 1
        self.families[family] += 1
        self.placements[placement] += 1
        return HttpVariant(family, placement, method, uri, body, content_type, r.choice(USER_AGENTS), variant_id)

    def metadata(self) -> dict:
        return {"version": VERSION, "seed": self.seed, "generated_requests": self.generated,
                "families": dict(self.families), "placements": dict(self.placements)}
