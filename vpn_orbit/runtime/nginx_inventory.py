"""Report literal HTTP server names from one supplied Nginx configuration."""

import argparse
import json
import re
import sys


MAX_CONFIG_BYTES = 1024 * 1024
_TOKEN = re.compile(
    rb"""[ \t\r\n]+|#[^\n]*|[;{}]|"(?:\\[\s\S]|[^"\\])*"|'(?:\\[\s\S]|[^'\\])*'"""
    rb"""|(?!#)(?:\\[\s\S]|\$\{[a-zA-Z0-9_]+\}|[^ \t\r\n;{}'"\\])+"""
)
_LABEL = rb"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_NAME = re.compile(_LABEL + rb"(?:\." + _LABEL + rb")+")


def _literal_name(token):
    if token[:1] in (b'"', b"'"):
        token = token[1:-1]
    token = token.lower().removesuffix(b".")
    if len(token) <= 253 and not token.rsplit(b".", 1)[-1].isdigit() and _NAME.fullmatch(token):
        return token.decode("ascii")
    return None


def inspect_config(config, *, http_fragment=False):
    if len(config) > MAX_CONFIG_BYTES or b"\0" in config:
        raise ValueError("unsupported Nginx input")
    contexts = []
    directive = []
    servers = []
    includes_unread = False
    pos = 0
    while pos < len(config):
        match = _TOKEN.match(config, pos)
        if match is None:
            raise ValueError("unsupported Nginx syntax")
        token = match[0]
        previous = config[pos - 1:pos] if pos else b""
        pos = match.end()
        if token[:1] in (b" ", b"\t", b"\r", b"\n", b"#"):
            continue

        if token == b"{":
            if not directive:
                raise ValueError("missing block directive")
            if directive == [b"http"] and not contexts and not http_fragment:
                context = "http"
            elif directive == [b"server"] and (contexts == ["http"] or http_fragment and not contexts):
                context = "server"
                servers.append({"names": [], "other_names": False})
            else:
                context = "other"
            contexts.append(context)
            directive.clear()
        elif token == b"}":
            if directive or not contexts:
                raise ValueError("unbalanced Nginx block")
            contexts.pop()
        elif token == b";":
            if not directive:
                raise ValueError("missing directive")
            if directive[0] == b"include" and "other" not in contexts:
                includes_unread = True
            if directive[0] == b"server_name" and contexts and contexts[-1] == "server":
                server = servers[-1]
                for argument in directive[1:]:
                    name = _literal_name(argument)
                    if name is None:
                        server["other_names"] = True
                    else:
                        server["names"].append(name)
            directive.clear()
        else:
            if token[:1] in (b'"', b"'"):
                boundaries = (b"", b" ", b"\t", b"\r", b"\n", b";", b"{", b"}")
                if previous not in boundaries or config[pos:pos + 1] not in boundaries:
                    raise ValueError("unsupported Nginx quoting")
            directive.append(token)

    if contexts or directive:
        raise ValueError("incomplete Nginx configuration")
    for server in servers:
        server["names"] = sorted(set(server["names"]))
    return {"scope": "SUPPLIED_CONFIG", "includes_unread": includes_unread, "servers": servers}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--http-fragment", action="store_true", help="input contains directives from the HTTP context")
    args = parser.parse_args(argv)
    try:
        report = inspect_config(sys.stdin.buffer.read(MAX_CONFIG_BYTES + 1), http_fragment=args.http_fragment)
    except (OSError, ValueError) as error:
        parser.error(str(error) if isinstance(error, ValueError) else "unable to read Nginx input")
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
