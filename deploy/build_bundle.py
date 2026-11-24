"""Build an installable Controller bundle.

A local build emits a v2 manifest authenticated by its SHA-256. An external
bundle can still be signed with an offline Ed25519 key that stays outside it.
"""

import argparse
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib

if __package__:
    from .artifact import AGE_FILE, AGE_SHA256, AGE_VERSION, FIXED_FILES, IMAGE, WEB_ASSET, WEB_INDEX, bundle_channel, canonical
else:
    from artifact import AGE_FILE, AGE_SHA256, AGE_VERSION, FIXED_FILES, IMAGE, WEB_ASSET, WEB_INDEX, bundle_channel, canonical


@contextmanager
def committed_source(root, commit):
    with tempfile.TemporaryDirectory(prefix="vpn-orbit-source-") as temporary:
        directory = Path(temporary)
        archive = directory / "source.tar"
        tree = directory / "tree"
        tree.mkdir()
        with archive.open("wb") as output:
            subprocess.run(["git", "archive", "--format=tar", commit], cwd=root, stdout=output, check=True)
        with tarfile.open(archive) as source:
            source.extractall(tree, filter="data")
        yield tree


def wheel_lock(root):
    pins = (root / "requirements-app.txt").read_text().splitlines()
    lines = (root / "deploy/requirements-wheels.lock").read_text().splitlines()
    if (len(pins) != len(lines) or any(
        not re.fullmatch(re.escape(pin) + r"(?: --hash=sha256:[0-9a-f]{64})+", line)
        for pin, line in zip(pins, lines, strict=True)
    )):
        raise ValueError("WHEEL_LOCK_MISMATCH")
    return root / "deploy/requirements-wheels.lock"


def package_web(tree, output):
    web = tree / "web"
    subprocess.run(["npm", "ci", "--engine-strict", "--ignore-scripts", "--no-audit", "--no-fund"],
                   cwd=web, check=True, timeout=180)
    subprocess.run(["npm", "run", "build"], cwd=web, check=True, timeout=120)
    dist = web / "dist"
    if not stat.S_ISDIR(dist.lstat().st_mode):
        raise ValueError("WEB_BUILD_INVALID")
    files = []
    for path in dist.rglob("*"):
        relative = "web/" + path.relative_to(dist).as_posix()
        info = path.lstat()
        if relative == "web/assets" and stat.S_ISDIR(info.st_mode):
            continue
        if ((relative != WEB_INDEX and not WEB_ASSET.fullmatch(relative)) or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1):
            raise ValueError("WEB_BUILD_INVALID")
        files.append(relative)
    if WEB_INDEX not in files or not any(name.endswith(".js") for name in files):
        raise ValueError("WEB_BUILD_INVALID")
    for name in files:
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(dist / name.removeprefix("web/"), target)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--signing-key", type=Path,
                        help="32-byte offline Ed25519 seed for an externally delivered bundle; never placed in the bundle")
    parser.add_argument("--unsigned", action="store_true",
                        help="Emit a SHA-256 authenticated manifest for a bundle built and installed locally")
    parser.add_argument("--python-image", required=True)
    parser.add_argument("--age-tool", type=Path, required=True, help="Official checksum-pinned age v1.3.2 linux/amd64 executable")
    parser.add_argument("--include-web", action="store_true", help="Build and include signed WebUI from the same commit; requires Node 26")
    args = parser.parse_args(argv)
    if (args.signing_key is None) == (not args.unsigned):
        parser.error("Choose either --signing-key for an external bundle or --unsigned for a local build")
    if args.include_web and args.unsigned:
        parser.error("Bundled WebUI requires a signed release")
    root = Path(__file__).resolve().parents[1]
    if sys.version_info[:2] != (3, 15) or re.fullmatch(IMAGE, args.python_image) is None:
        parser.error("Python 3.15 and an official digest-pinned Python image are required")
    output = args.output.absolute()
    if output.exists() or (args.signing_key is not None and args.signing_key.resolve().is_relative_to(output)):
        parser.error("Output must be new and the signing key must be independent")
    signer = None
    if args.signing_key is not None:
        seed = args.signing_key.read_bytes()
        if len(seed) != 32:
            parser.error("The Ed25519 seed must be exactly 32 bytes")
        from nacl.signing import SigningKey
        signer = SigningKey(seed)
    age = args.age_tool.read_bytes()
    if hashlib.sha256(age).hexdigest() != AGE_SHA256:
        parser.error("Unsupported age binary; expected the pinned official linux/amd64 release")
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root).decode().strip()
    if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=root).strip():
        parser.error("Build from a committed source revision")
    with committed_source(root, source) as tree:
        metadata = json.loads((tree / "vpn_orbit/release-manifest.json").read_text())
        sqlite_schema = metadata["sqlite_schema"]
        version = tomllib.loads((tree / "pyproject.toml").read_text())["project"]["version"]
        channel = bundle_channel(version)
        if channel is None or metadata["version"] != version or metadata["channel"] != channel:
            parser.error("Package version and release manifest must agree on a supported channel")
        try:
            requirements = wheel_lock(tree)
        except ValueError:
            parser.error("Release wheel hashes do not match requirements-app.txt")
        output.mkdir(mode=0o700, parents=True)
        wheels = output / "wheelhouse"
        wheels.mkdir()
        build_env = tree.parent / "build-env"
        subprocess.run([sys.executable, "-m", "venv", str(build_env)], check=True)
        build_python = build_env / "bin/python"
        subprocess.run([str(build_python), "-m", "pip", "install", "--only-binary=:all:", "--require-hashes",
                        "-r", str(tree / "deploy/requirements-build.lock")], check=True)
        subprocess.run([str(build_python), "-m", "pip", "download", "--only-binary=:all:", "--require-hashes", "--dest", str(wheels),
                        "-r", str(requirements)], check=True)
        subprocess.run([str(build_python), "-m", "pip", "wheel", "--no-deps", "--no-build-isolation",
                        "--wheel-dir", str(wheels), str(tree)], check=True)
        for relative in FIXED_FILES - {"requirements-install.txt", "sbom.cdx.json"}:
            path = output / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(tree / relative, path)
        if args.include_web:
            package_web(tree, output)
    (output / AGE_FILE).parent.mkdir(mode=0o755)
    (output / AGE_FILE).write_bytes(age)
    # The bundle carries exactly the resolved binary distributions. pip on the
    # host and in the image installs these bytes with hashes and no index.
    locked, components = [], []
    for path in sorted(wheels.glob("*.whl")):
        name, wheel_version, *_ = path.name.split("-")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        locked.append(f"{name}=={wheel_version} --hash=sha256:{digest}")
        components.append({"type": "library", "name": name, "version": wheel_version,
                           "purl": f"pkg:pypi/{name.lower().replace('_', '-')}@{wheel_version}",
                           "hashes": [{"alg": "SHA-256", "content": digest}]})
    (output / "requirements-install.txt").write_text("\n".join(locked) + "\n", encoding="utf-8")
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": {"type": "application", "name": "VPN-Orbit", "version": version},
                         "properties": [{"name": "vpn-orbit:scope", "value": "Installed Python wheels plus the pinned OCI base; excludes full OS/base image inventory"}]},
            "components": components + [{"type": "container", "name": args.python_image},
                                         {"type": "application", "name": "age", "version": AGE_VERSION,
                                          "hashes": [{"alg": "SHA-256", "content": AGE_SHA256}]}]}
    (output / "sbom.cdx.json").write_bytes(canonical(sbom))
    files = [{"path": str(path.relative_to(output)), "size": path.stat().st_size,
              "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
             for path in sorted(output.rglob("*")) if path.is_file()]
    if signer is None:
        value = {"v": 2, "application": "VPN-Orbit", "version": version, "channel": channel,
                 "source_commit": source, "python_image": args.python_image, "platform": "ubuntu-24.04-amd64",
                 "python": "3.15", "sqlite_schema": sqlite_schema, "remote_mutation_enabled": False,
                 "authentication": "sha256", "files": files}
        data = canonical(value)
        (output / "manifest.json").write_bytes(data)
        result = {"bundle": str(output), "manifest_sha256": hashlib.sha256(data).hexdigest(),
                  "authentication": "sha256", "channel": channel}
    else:
        value = {"v": 1, "application": "VPN-Orbit", "version": version, "channel": channel,
                 "source_commit": source, "python_image": args.python_image, "platform": "ubuntu-24.04-amd64",
                 "python": "3.15", "sqlite_schema": sqlite_schema, "remote_mutation_enabled": False, "files": files,
                 "signing_key_sha256": hashlib.sha256(bytes(signer.verify_key)).hexdigest()}
        data = canonical(value)
        (output / "manifest.json").write_bytes(data)
        (output / "manifest.sig").write_bytes(signer.sign(data).signature)
        result = {"bundle": str(output), "manifest_sha256": hashlib.sha256(data).hexdigest(),
                  "authentication": "signature", "signing_key_sha256": value["signing_key_sha256"],
                  "channel": channel}
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
