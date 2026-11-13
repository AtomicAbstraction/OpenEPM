#!/usr/bin/env python3
"""Stage a versioned landing candidate or capture the running recovery site."""

from __future__ import annotations

import argparse
from hashlib import sha256
from html.parser import HTMLParser
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from tempfile import TemporaryDirectory
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "public-landing"
RELEASES = ROOT / ".epm-runtime/public-landing/releases"
SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,79}")
CORE_FILES = (
    "index.html", "request-access/index.html", "server.mjs", "http.mjs",
    "documentation/manifest.json", "documentation/render.mjs",
    "documentation/documentation.css", "documentation/comments.mjs",
    "documentation/discussion-store.mjs", "firebase.json",
    "firestore.rules", "firestore.indexes.json", "knowledge-graph/index.html",
    "knowledge-graph/viewer.js", "knowledge-graph/renderer.js", "knowledge-graph/LICENSE.txt",
)
BASE_ROUTES = (
    "/", "/index.html", "/request-access/", "/request-access",
    "/request-access/index.html", "/documentation/", "/documentation",
    "/documentation/index.html", "/documentation/comments.mjs",
)
RECOVERY_SERVER = """import { readFileSync } from "node:fs";
import { listen } from "./http.mjs";

const read = (path) => readFileSync(new URL(path, import.meta.url));
const records = JSON.parse(read("./responses.json"));
const pages = new Map(Object.entries(records).map(([route, record]) => [
  route,
  { content: read("./responses/" + record.sha256), contentType: record.contentType,
    contentSecurityPolicy: record.contentSecurityPolicy },
]));
listen(pages);
"""
VALIDATE_RENDERED_LINKS = """import { readFileSync } from "node:fs";

const origin = "https://openepm.dev";
const documents = JSON.parse(readFileSync(0, "utf8"));
const targets = new Map();
for (const [routes, anchors] of documents) {
  const ids = anchors === null ? null : new Set(anchors);
  for (const route of routes) targets.set(route, ids);
}

function firstError() {
  for (const [routes, , references] of documents) {
    for (const route of routes) {
      for (const reference of references) {
        let url;
        try {
          url = new URL(reference, origin + route);
        } catch {
          return `Invalid URL on ${route}: ${reference}`;
        }
        if (url.origin !== origin && url.origin !== "http://openepm.dev") continue;
        if (!targets.has(url.pathname)) return `Unknown site path on ${route}: ${reference}`;
        const anchors = targets.get(url.pathname);
        if (!url.hash || !anchors) continue;
        let anchor;
        try {
          anchor = decodeURIComponent(url.hash.slice(1));
        } catch {
          return `Invalid site anchor on ${route}: ${reference}`;
        }
        if (anchor.toLowerCase() !== "top" && !anchors.has(anchor)) {
          return `Unknown site anchor on ${route}: ${reference}`;
        }
      }
    }
  }
  return "";
}
process.stdout.write(firstError());
"""


def inventory(directory):
    return {
        path.relative_to(directory).as_posix(): sha256(path.read_bytes()).hexdigest()
        for path in sorted(directory.rglob("*"))
        if path.is_file() and path.name != "release.json"
    }


def copy_candidate(destination):
    manifest = json.loads((SOURCE / "documentation/manifest.json").read_text())
    files = list(CORE_FILES)
    for page in manifest["pages"]:
        slug = page["id"]
        if not SLUG.fullmatch(slug) or page["contentFile"] != f"pages/{slug}.html":
            raise ValueError(f"Invalid landing source path for {slug}")
        files.append(f"documentation/{page['contentFile']}")
    for relative in files:
        source = SOURCE / relative
        if not source.is_file() or source.resolve() != source:
            raise ValueError(f"Missing or noncanonical landing source {relative}")
        output = destination / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, output)


class RenderedLinks(HTMLParser):
    def __init__(self, html, route):
        super().__init__()
        self.route = route
        self.ids = set()
        self.anchors = set()
        self.references = set()
        self.feed(html)
        self.close()

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        identifier = attributes.get("id")
        if identifier:
            if identifier in self.ids:
                raise ValueError(f"Duplicate HTML ID {identifier!r} on {self.route}")
            self.ids.add(identifier)
        if tag == "a" and attributes.get("name"):
            self.anchors.add(attributes["name"])
        self.references.update(value for name, value in attrs if name in {"href", "src"} and value)


def validate_candidate(directory):
    result = subprocess.run(
        ["node", str(directory / "server.mjs"), "--export-pages"],
        env={**os.environ, "OPEN_EPM_LANDING_ROOT": str(directory)},
        stdout=subprocess.PIPE, encoding="utf-8", check=True, timeout=30,
    )
    documents = []
    for routes, html in json.loads(result.stdout):
        if html is None:
            documents.append((routes, None, []))
        else:
            page = RenderedLinks(html, routes[0])
            documents.append((routes, sorted(page.ids | page.anchors), sorted(page.references)))
    # Use the browser's URL rules for relative links, encoded path segments and fragments.
    validation = subprocess.run(
        ["node", "--input-type=module", "-e", VALIDATE_RENDERED_LINKS],
        input=json.dumps(documents), stdout=subprocess.PIPE, encoding="utf-8",
        check=True, timeout=30,
    )
    if validation.stdout:
        raise ValueError(validation.stdout)


class LocalLinks(HTMLParser):
    def __init__(self, body):
        super().__init__()
        self.routes = set()
        self.feed(body.decode("utf-8"))
        self.close()

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if name not in ("href", "src") or not value or not value.startswith("/"):
                continue
            target = urlsplit(value)
            if (not target.netloc
                    and re.fullmatch(r"/documentation/[a-z0-9][a-z0-9-]{0,79}/", target.path)):
                self.routes.update((target.path, target.path.rstrip("/")))
            if (not target.netloc
                    and re.fullmatch(r"/documentation/[a-z0-9-]+\.(mjs|css)", target.path)):
                self.routes.add(target.path)
            if not target.netloc and target.path == "/knowledge-graph/":
                self.routes.update(("/knowledge-graph", "/knowledge-graph/", "/knowledge-graph/LICENSE.txt"))
            if not target.netloc and target.path in {"/knowledge-graph/renderer.js", "/knowledge-graph/viewer.js"}:
                self.routes.add(target.path)


def capture_running_site(destination):
    responses = {}
    (destination / "responses").mkdir()
    pending = set(BASE_ROUTES)
    while pending:
        route = min(pending)
        pending.remove(route)
        if route in responses:
            continue
        connection = HTTPConnection("127.0.0.1", 5186, timeout=5)
        try:
            connection.request("GET", route)
            response = connection.getresponse()
            content_type = response.getheader("Content-Type")
            content_security_policy = response.getheader("Content-Security-Policy")
            limit = 3_000_000 if route.startswith("/knowledge-graph") else 1_000_000
            body = response.read(limit + 1)
            if (response.status != 200 or not content_type or len(body) > limit
                    or response.getheader("Content-Length") != str(len(body))):
                raise RuntimeError(f"Could not capture bounded response for {route}")
        finally:
            connection.close()
        digest = sha256(body).hexdigest()
        (destination / "responses" / digest).write_bytes(body)
        responses[route] = {"sha256": digest, "contentType": content_type}
        if content_security_policy:
            responses[route]["contentSecurityPolicy"] = content_security_policy
        if content_type.startswith("text/html"):
            pending.update(LocalLinks(body).routes - responses.keys())
        if (route == "/documentation/comments.mjs"
                and b'from "./discussion-store.mjs"' in body):
            pending.add("/documentation/discussion-store.mjs")
        if len(responses) + len(pending) > 500:
            raise RuntimeError("Landing recovery route inventory exceeded its expected bound")
    (destination / "responses.json").write_text(json.dumps(responses, indent=2) + "\n")
    (destination / "server.mjs").write_text(RECOVERY_SERVER)
    shutil.copyfile(SOURCE / "http.mjs", destination / "http.mjs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("site", "recovery"))
    args = parser.parse_args()
    RELEASES.mkdir(mode=0o700, parents=True, exist_ok=True)
    if RELEASES.resolve() != RELEASES:
        raise ValueError("Landing release directory must be canonical")
    with TemporaryDirectory(prefix=".stage-", dir=RELEASES) as scratch:
        staging = Path(scratch) / "release"
        staging.mkdir()
        if args.kind == "site":
            copy_candidate(staging)
            validate_candidate(staging)
        else:
            capture_running_site(staging)
        files = inventory(staging)
        identity = sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
        release = RELEASES / f"{args.kind}-{identity}"
        record = {"kind": args.kind, "sha256": identity, "files": files}
        if release.exists():
            if (release.resolve() != release or inventory(release) != files
                    or any(path.is_symlink() for path in release.rglob("*"))
                    or json.loads((release / "release.json").read_text()) != record):
                raise ValueError(f"Existing landing release does not match {identity}")
        else:
            (staging / "release.json").write_text(json.dumps(record, indent=2) + "\n")
            for path in staging.rglob("*"):
                path.chmod(0o555 if path.is_dir() else 0o444)
            os.rename(staging, release)
            release.chmod(0o555)
    print(release)


if __name__ == "__main__":
    main()
