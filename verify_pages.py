"""Verify the static site with Python's stdlib and Node's JavaScript parser."""

from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
import re
import shutil
import subprocess
from urllib.parse import unquote, urlsplit


VOID = set("area base br col embed hr img input link meta param source track wbr".split())
ASSET_ATTRS = {"script": "src", "link": "href", "img": "src", "source": "src"}
JS_TYPES = {"", "module", "text/javascript", "application/javascript", "text/ecmascript"}
CSS_REFERENCE = re.compile(r"url\(\s*(['\"]?)(.*?)\1\s*\)|@import\s*(['\"])(.*?)\3", re.I | re.S)
SENSITIVE = {
    "possible credential": re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:gh[pousr]_[A-Za-z0-9]{30,}|"
        r"github_pat_[A-Za-z0-9_]{30,}|sk-[A-Za-z0-9_-]{24,}|"
        r"(?:AKIA|ASIA)[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{14,}|"
        r"eyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,})\b|"
        r"\bBearer\s+[A-Za-z0-9._-]{20,}|"
        r"\b(?:api[_-]?key|password|secret|access[_-]?token)['\"]?\s*[:=]\s*"
        r"['\"][A-Za-z0-9+/_.@!$-]{16,}['\"]",
        re.I,
    ),
    "machine-local path": re.compile(
        r"\b[A-Z]:[\\/]+|\bfile:/+|\\\\[\w.-]+\\+[\w.-]+|"
        r"(?<![\w/.:])/(?:Users|home|mnt|Volumes|private|var/folders|tmp)/",
        re.I,
    ),
}


class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.counts = Counter()
        self.doctypes = 0
        self.ids = set()
        self.dependencies = []
        self.scripts = []
        self.styles = []
        self.errors = []

    def error(self, message):
        self.errors.append(f"index.html:{self.getpos()[0]}: {message}")

    def handle_decl(self, declaration):
        if declaration.strip().lower() == "doctype html" and not self.counts:
            self.doctypes += 1
        else:
            self.error("expected <!doctype html> before the document")

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        self.counts[tag] += 1
        parent = self.stack[-1][0] if self.stack else None
        if not self.stack and tag != "html":
            self.error(f"<{tag}> is outside the document")
        expected_parent = {"head": "html", "body": "html", "title": "head"}.get(tag)
        if expected_parent and parent != expected_parent:
            self.error(f"<{tag}> is in the wrong part of the document")
        if len(attributes) != len(attrs):
            self.error(f"duplicate attribute on <{tag}>")
        if tag == "html" and not attributes.get("lang"):
            self.error("<html> requires a language")
        if tag == "base":
            self.error("<base> can break relative asset URLs")

        element_id = attributes.get("id")
        if element_id in self.ids:
            self.error("duplicate id attribute")
        if element_id:
            self.ids.add(element_id)

        asset_attr = ASSET_ATTRS.get(tag)
        if asset_attr in attributes:
            self.dependencies.append((tag, attributes[asset_attr] or ""))
        if attributes.get("style"):
            self.styles.append(attributes["style"])
        if tag not in VOID:
            self.stack.append((tag, attributes, [], self.getpos()[0]))

    def handle_startendtag(self, tag, attrs):
        if tag not in VOID and tag != "svg" and not any(node[0] == "svg" for node in self.stack):
            self.error(f"<{tag}> requires an explicit closing tag")
        self.handle_starttag(tag, attrs)
        if tag not in VOID:
            self.handle_endtag(tag)

    def handle_data(self, data):
        if self.stack and self.stack[-1][0] in {"script", "style"}:
            self.stack[-1][2].append(data)

    def handle_endtag(self, tag):
        if not self.stack or self.stack[-1][0] != tag:
            self.error(f"unexpected </{tag}>")
            return
        _, attributes, parts, line = self.stack.pop()
        if tag == "style":
            self.styles.append("".join(parts))
        if tag == "script":
            script_type = (attributes.get("type") or "").strip().lower()
            if script_type in JS_TYPES:
                if attributes.get("src"):
                    self.scripts.append((attributes["src"], None, script_type))
                else:
                    self.scripts.append((f"index.html:{line} inline script", "".join(parts), script_type))


def asset_path(root, reference, allow_data, errors, label):
    reference = reference.strip()
    try:
        url = urlsplit(reference)
    except ValueError:
        errors.append(f"{label}: invalid asset URL")
        return None
    if allow_data and (reference.startswith("#") or (
        url.scheme == "data" and url.path.lower().startswith(("image/", "font/"))
    )):
        return None
    if url.scheme or url.netloc or reference.startswith(('/', '\\')):
        errors.append(f"{label}: asset URL must be relative or embedded")
        return None
    path = (root / unquote(url.path)).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        errors.append(f"{label}: missing or out-of-directory asset")
        return None
    return path


def check_javascript(scripts, errors):
    node = shutil.which("node")
    if not node:
        errors.append("Node.js is needed to parse JavaScript during verification")
        return
    for label, source, script_type in scripts:
        command = [node, "--check", "--input-type=module", "-"] if script_type == "module" else [
            node, "-e", "new (require('node:vm').Script)(require('node:fs').readFileSync(0, 'utf8'))",
        ]
        result = subprocess.run(
            command, input=source, capture_output=True, encoding="utf-8", timeout=15, check=False,
        )
        if result.returncode:
            detail = re.search(r"^SyntaxError: .+$", result.stderr, re.MULTILINE)
            errors.append(f"{label}: {detail[0] if detail else 'JavaScript parser failed'}")


def verify(root):
    page_path = root / "index.html"
    if not page_path.is_file():
        return ["index.html is missing"]
    sources = {
        path: path.read_text(encoding="utf-8-sig")
        for path in root.iterdir()
        if path.is_file() and path.suffix.lower() in {".html", ".css", ".js"}
    }

    page = Page()
    page.feed(sources[page_path])
    page.close()
    errors = page.errors
    if page.stack:
        errors.append(f"index.html: unclosed <{page.stack[-1][0]}>")
    if page.doctypes != 1:
        errors.append("index.html: expected one HTML doctype")
    for tag in ("html", "head", "title", "body", "main"):
        if page.counts[tag] != 1:
            errors.append(f"index.html: expected one <{tag}>")

    for tag, reference in page.dependencies:
        path = asset_path(root, reference, tag in {"link", "img", "source"}, errors, f"index.html <{tag}>")
        if path and path.suffix.lower() in {".css", ".js"} and path not in sources:
            sources[path] = path.read_text(encoding="utf-8-sig")
    for path, source in sources.items():
        for kind, pattern in SENSITIVE.items():
            match = pattern.search(source)
            if match:
                line = source.count("\n", 0, match.start()) + 1
                errors.append(f"{path.name}:{line}: {kind}")
    styles = [(path.parent, path.name, source) for path, source in sources.items() if path.suffix.lower() == ".css"]
    styles.extend((root, "index.html style", style) for style in page.styles)
    for directory, label, source in styles:
        for match in CSS_REFERENCE.finditer(source):
            asset_path(directory, match[2] if match[2] is not None else match[4], True, errors, label)

    copy = "\n".join(source for path, source in sources.items() if path.suffix.lower() != ".css")
    if len(re.findall(r"[\u3400-\u9fff]", copy)) < 20 or not re.search(r"\b(?:en|english)\b", copy, re.I):
        errors.append("English and Chinese UI strings are required")

    scripts = []
    linked_scripts = set()
    for label, source, script_type in page.scripts:
        if source is None:
            path = asset_path(root, label, False, [], "script")
            if not path:
                continue
            linked_scripts.add(path)
            label, source = path.name, path.read_text(encoding="utf-8-sig")
        scripts.append((label, source, script_type))
    scripts.extend((path.name, source, "") for path, source in sources.items()
                   if path.suffix.lower() == ".js" and path not in linked_scripts)
    if not errors:
        check_javascript(scripts, errors)
    return errors


def main():
    try:
        errors = verify(Path(__file__).resolve().parent)
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as error:
        print(f"FAIL: verification failed ({type(error).__name__})")
        return 1
    if errors:
        for error in errors:
            print(f"FAIL: {error}")
        return 1
    print("PASS: HTML structure, local assets, JavaScript syntax, bilingual strings, and leak scan.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
