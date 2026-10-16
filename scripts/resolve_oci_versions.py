#!/usr/bin/env python3
"""Resolve installable PyPI releases used by the OCI appliance."""

from __future__ import annotations

import argparse
import http.client
import json
import re
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from functools import lru_cache
from pathlib import Path

from packaging.specifiers import SpecifierSet
from packaging.tags import Tag, compatible_tags
from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    canonicalize_name,
    parse_sdist_filename,
    parse_wheel_filename,
)
from packaging.version import InvalidVersion, Version


PYPI_JSON = "https://pypi.org/pypi/{package}/json"
PYPI_SIMPLE = "https://pypi.org/simple/{package}/"
PYPI_SIMPLE_JSON = "application/vnd.pypi.simple.v1+json"
DEFAULT_COMPATIBILITY_FILE = Path(__file__).resolve().parents[1] / "COMPATIBILITY.md"
PAIRING_HEADER = ("netbox-proxbox", "NetBox", "Python", "proxbox-api")


def _metadata(package: str) -> dict:
    with urllib.request.urlopen(
        PYPI_JSON.format(package=package), timeout=30
    ) as response:
        return json.load(response)


def _simple_index(package: str) -> dict:
    request = urllib.request.Request(
        PYPI_SIMPLE.format(package=canonicalize_name(package)),
        headers={"Accept": PYPI_SIMPLE_JSON},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def _file_metadata_is_compatible(file: dict, python_version: Version) -> bool:
    requirement = file.get("requires_python") or file.get("requires-python") or ""
    return not file.get("yanked", False) and (
        not requirement or python_version in SpecifierSet(requirement)
    )


@lru_cache(maxsize=None)
def _compatible_pure_python_tags(python_version: Version) -> frozenset[Tag]:
    major, minor = python_version.release[:2]
    return frozenset(
        tag
        for tag in compatible_tags(
            python_version=(major, minor), interpreter=f"cp{major}{minor}"
        )
        if tag.abi == "none" and tag.platform == "any"
    )


def _filename_version(filename: str, supported_tags: frozenset[Tag]) -> Version | None:
    try:
        if filename.endswith((".tar.gz", ".zip")):
            return parse_sdist_filename(filename)[1]
        if not filename.endswith(".whl"):
            return None
        _, version, _, tags = parse_wheel_filename(filename)
    except (InvalidWheelFilename, InvalidSdistFilename):
        return None
    if tags & supported_tags:
        return version
    return None


def _file_is_compatible(
    file: dict, python_version: Version, supported_tags: frozenset[Tag]
) -> bool:
    return _filename_version(file.get("filename", ""), supported_tags) is not None and (
        _file_metadata_is_compatible(file, python_version)
    )


def _compatible_versions(releases: dict, python_version: Version) -> list[Version]:
    """Return stable versions that have a compatible, non-yanked file."""
    candidates: list[Version] = []
    supported_tags = _compatible_pure_python_tags(python_version)
    for raw_version, files in releases.items():
        version = Version(raw_version)
        if version.is_prerelease or version.is_devrelease:
            continue
        for file in files:
            if not _file_is_compatible(file, python_version, supported_tags):
                continue
            candidates.append(version)
            break
    return candidates


def _simple_compatible_versions(index: dict, python_version: Version) -> set[Version]:
    versions: set[Version] = set()
    supported_tags = _compatible_pure_python_tags(python_version)
    for file in index.get("files", []):
        version = _filename_version(file.get("filename", ""), supported_tags)
        if version is not None and _file_metadata_is_compatible(file, python_version):
            versions.add(version)
    return versions


_TRANSIENT = (
    urllib.error.URLError,
    http.client.HTTPException,
    TimeoutError,
    OSError,
    ValueError,
)
Fetch = Callable[[str], dict]


def retrying_fetch(
    *,
    reader: Fetch | None = None,
    source: str = "metadata",
    wait_seconds: int = 0,
    poll_seconds: int = 30,
    sleep: Callable[[float], None] | None = None,
    monotonic: Callable[[], float] | None = None,
    deadline: float | None = None,
) -> Fetch:
    """Return a PyPI reader that retries transient errors until a deadline."""
    sleep = sleep or time.sleep
    monotonic = monotonic or time.monotonic
    deadline = deadline if deadline is not None else monotonic() + wait_seconds
    reader = reader or _metadata

    def fetch(package: str) -> dict:
        while True:
            try:
                return reader(package)
            except _TRANSIENT as error:
                if monotonic() >= deadline:
                    raise RuntimeError(
                        f"PyPI {source} for {package} is unavailable ({error})"
                    ) from error
                sleep(poll_seconds)

    return fetch


def latest_compatible(
    package: str,
    python_version: Version,
    *,
    fetch: Fetch | None = None,
    simple_fetch: Fetch | None = None,
) -> Version:
    """Return the newest stable release installable through both PyPI APIs."""
    releases = (fetch or _metadata)(package)["releases"]
    simple = (simple_fetch or _simple_index)(package)
    candidates = set(_compatible_versions(releases, python_version))
    candidates &= _simple_compatible_versions(simple, python_version)
    if not candidates:
        raise RuntimeError(
            f"PyPI has no stable {package} artifact compatible with Python "
            f"{python_version} in both the JSON metadata API and simple index"
        )
    return max(candidates)


def newest_published(package: str, *, fetch: Fetch | None = None) -> Version:
    """Return the newest stable release ever published, even if yanked.

    Promotion order must not depend on installation eligibility: a yanked or
    Python-incompatible newer release still owns the moving image tag.
    """
    releases = (fetch or _metadata)(package)["releases"]
    versions = [
        version
        for raw, files in releases.items()
        if files
        for version in [Version(raw)]
        if not (version.is_prerelease or version.is_devrelease)
    ]
    if not versions:
        raise RuntimeError(f"PyPI has no stable {package} release")
    return max(versions)


def exact_compatible(
    package: str,
    wanted: Version,
    python_version: Version,
    *,
    wait_seconds: int = 0,
    poll_seconds: int = 30,
    sleep: Callable[[float], None] | None = None,
    monotonic: Callable[[], float] | None = None,
    fetch: Fetch | None = None,
    simple_fetch: Fetch | None = None,
    deadline: float | None = None,
) -> Version:
    """Return ``wanted`` once both PyPI APIs serve an installable artifact.

    Polls until ``wait_seconds`` elapse so a release build does not race the
    PyPI publication of the same release.
    """
    if wanted.is_prerelease or wanted.is_devrelease:
        raise RuntimeError(
            f"{package} {wanted} is a prerelease and is not published as an image"
        )
    sleep = sleep or time.sleep
    monotonic = monotonic or time.monotonic
    deadline = deadline if deadline is not None else monotonic() + wait_seconds
    read = fetch or retrying_fetch(
        wait_seconds=wait_seconds,
        poll_seconds=poll_seconds,
        sleep=sleep,
        monotonic=monotonic,
        deadline=deadline,
    )
    read_simple = simple_fetch or retrying_fetch(
        reader=_simple_index,
        source="simple index",
        wait_seconds=wait_seconds,
        poll_seconds=poll_seconds,
        sleep=sleep,
        monotonic=monotonic,
        deadline=deadline,
    )
    while True:
        metadata_versions = _compatible_versions(
            read(package)["releases"], python_version
        )
        simple_versions = _simple_compatible_versions(
            read_simple(package), python_version
        )
        metadata_ready = wanted in metadata_versions
        simple_ready = wanted in simple_versions
        if metadata_ready and simple_ready:
            return wanted
        if monotonic() >= deadline:
            missing = []
            if not metadata_ready:
                missing.append("JSON metadata API")
            if not simple_ready:
                missing.append("simple install index")
            raise RuntimeError(
                f"PyPI has no installable stable {package} {wanted} artifact "
                f"compatible with Python {python_version}; missing from "
                f"{' and '.join(missing)}"
            )
        sleep(poll_seconds)


def _markdown_cells(line: str) -> list[str] | None:
    stripped = line.strip()
    if not stripped.startswith("|") or not stripped.endswith("|"):
        return None
    return [cell.strip() for cell in stripped[1:-1].split("|")]


def _compatibility_rows(
    compatibility_file: Path, plugin_version: Version
) -> list[tuple[int, list[str]]]:
    """Return rows from the one declared release-pairing table."""
    try:
        lines = compatibility_file.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise RuntimeError(
            f"Cannot read compatibility pairing file {compatibility_file} for "
            f"netbox-proxbox {plugin_version}: {error}"
        ) from error

    header_indexes = [
        index
        for index, line in enumerate(lines)
        if tuple((_markdown_cells(line) or [])[:4]) == PAIRING_HEADER
    ]
    if len(header_indexes) != 1:
        raise RuntimeError(
            f"Compatibility pairing file {compatibility_file} must contain exactly "
            f"one release-pairing table for netbox-proxbox {plugin_version}"
        )

    header_index = header_indexes[0]
    separator_index = header_index + 1
    separator = (
        _markdown_cells(lines[separator_index])
        if separator_index < len(lines)
        else None
    )
    if separator is None or not all(
        re.fullmatch(r":?-{3,}:?", cell) for cell in separator
    ):
        raise RuntimeError(
            f"Compatibility pairing table in {compatibility_file} is malformed for "
            f"netbox-proxbox {plugin_version}"
        )

    rows: list[tuple[int, list[str]]] = []
    for index in range(separator_index + 1, len(lines)):
        cells = _markdown_cells(lines[index])
        if cells is None:
            break
        if len(cells) != len(separator):
            raise RuntimeError(
                f"Compatibility pairing row {index + 1} in {compatibility_file} is "
                f"malformed for netbox-proxbox {plugin_version}"
            )
        rows.append((index + 1, cells))
    return rows


def _version_cell(
    value: str,
    *,
    package: str,
    compatibility_file: Path,
    plugin_version: Version,
    row_number: int,
) -> Version:
    normalized = value.removeprefix("v")
    try:
        version = Version(normalized)
    except InvalidVersion as error:
        raise RuntimeError(
            f"Compatibility pairing file {compatibility_file} has malformed "
            f"{package} version {value!r} on row {row_number} for "
            f"netbox-proxbox {plugin_version}"
        ) from error
    if normalized != str(version):
        raise RuntimeError(
            f"Compatibility pairing file {compatibility_file} has non-canonical "
            f"{package} version {value!r} on row {row_number} for "
            f"netbox-proxbox {plugin_version}"
        )
    return version


def paired_backend_version(
    plugin_version: Version, compatibility_file: Path
) -> Version:
    """Return the backend paired with a release in ``COMPATIBILITY.md``."""
    matches: list[tuple[int, list[str]]] = []
    for row_number, cells in _compatibility_rows(compatibility_file, plugin_version):
        row_plugin = _version_cell(
            cells[0],
            package="netbox-proxbox",
            compatibility_file=compatibility_file,
            plugin_version=plugin_version,
            row_number=row_number,
        )
        if row_plugin == plugin_version:
            matches.append((row_number, cells))

    if len(matches) != 1:
        problem = "no row" if not matches else f"{len(matches)} duplicate rows"
        raise RuntimeError(
            f"Compatibility pairing file {compatibility_file} has {problem} for "
            f"netbox-proxbox {plugin_version}; exactly one row is required"
        )

    row_number, cells = matches[0]
    return _version_cell(
        cells[3],
        package="proxbox-api",
        compatibility_file=compatibility_file,
        plugin_version=plugin_version,
        row_number=row_number,
    )


def tag_to_version(tag: str) -> Version:
    """Map a release tag such as ``v0.0.29.post2`` to its package version."""
    return Version(tag.removeprefix("v"))


def _write_outputs(values: dict[str, str], destination: Path | None) -> None:
    output = "\n".join(f"{key}={value}" for key, value in values.items()) + "\n"
    if destination:
        with destination.open("a", encoding="utf-8") as handle:
            handle.write(output)
    else:
        print(output, end="")


def _check_promotion(args: argparse.Namespace) -> int:
    """Report whether the version may move the mutable image tag.

    Called after the versioned image is published, with fresh metadata, so a
    newer release that appeared during the build is still honored.
    """
    fetch = retrying_fetch(
        wait_seconds=args.wait_seconds, poll_seconds=args.poll_seconds
    )
    version = tag_to_version(args.check_promotion)
    newest = newest_published("netbox-proxbox", fetch=fetch)
    # The mutable image tag must never move to an older release.
    _write_outputs(
        {"publish_moving_tag": str(version >= newest).lower()}, args.github_output
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--netbox-python", default="3.14")
    parser.add_argument("--proxbox-api-python", default="3.13")
    parser.add_argument("--github-output", type=Path)
    parser.add_argument(
        "--plugin-version",
        help="exact netbox-proxbox release tag or version to install",
    )
    parser.add_argument(
        "--compatibility-file",
        type=Path,
        default=DEFAULT_COMPATIBILITY_FILE,
        help="authoritative release-pairing table",
    )
    parser.add_argument(
        "--check-promotion",
        metavar="VERSION",
        help="report whether VERSION may move the mutable image tag, then exit",
    )
    parser.add_argument("--wait-seconds", type=int, default=0)
    parser.add_argument("--poll-seconds", type=int, default=30)
    args = parser.parse_args()
    if args.check_promotion:
        return _check_promotion(args)

    requested_plugin = None
    paired_backend = None
    if args.plugin_version:
        requested_plugin = tag_to_version(args.plugin_version)
        if requested_plugin.is_prerelease or requested_plugin.is_devrelease:
            raise RuntimeError(
                f"netbox-proxbox {requested_plugin} is a prerelease and is not "
                "published as an image"
            )
        paired_backend = paired_backend_version(
            requested_plugin, args.compatibility_file
        )

    netbox_python = Version(args.netbox_python)
    backend_python = Version(args.proxbox_api_python)
    deadline = time.monotonic() + args.wait_seconds
    fetch = retrying_fetch(
        wait_seconds=args.wait_seconds,
        poll_seconds=args.poll_seconds,
        deadline=deadline,
    )
    simple_fetch = retrying_fetch(
        reader=_simple_index,
        source="simple index",
        wait_seconds=args.wait_seconds,
        poll_seconds=args.poll_seconds,
        deadline=deadline,
    )
    if requested_plugin is not None and paired_backend is not None:
        plugin_version = exact_compatible(
            "netbox-proxbox",
            requested_plugin,
            netbox_python,
            wait_seconds=args.wait_seconds,
            poll_seconds=args.poll_seconds,
            fetch=fetch,
            simple_fetch=simple_fetch,
            deadline=deadline,
        )
        backend_version = exact_compatible(
            "proxbox-api",
            paired_backend,
            backend_python,
            wait_seconds=args.wait_seconds,
            poll_seconds=args.poll_seconds,
            fetch=fetch,
            simple_fetch=simple_fetch,
            deadline=deadline,
        )
    else:
        plugin_version = latest_compatible(
            "netbox-proxbox",
            netbox_python,
            fetch=fetch,
            simple_fetch=simple_fetch,
        )
        backend_version = latest_compatible(
            "proxbox-api",
            backend_python,
            fetch=fetch,
            simple_fetch=simple_fetch,
        )

    values = {
        "netbox_proxbox_version": str(plugin_version),
        "proxbox_api_version": str(backend_version),
        "proxbox_api_python": str(backend_python),
    }
    _write_outputs(values, args.github_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
