"""定向收集 Ubuntu libc 版本到 data/libc/raw/db。"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
import ssl
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from urllib.error import URLError


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RAW_DIR = PROJECT_ROOT / "data" / "libc" / "raw"

DEFAULT_ARCHES = ("amd64", "i386")
DEFAULT_PACKAGES = ("libc6", "libc6-i386", "libc6-amd64")

PRESET_MAJORS: dict[str, tuple[str, ...]] = {
    # PWN 高频大版本，优先拉细小补丁版本。
    "common-pwn": ("2.19", "2.23", "2.27", "2.31", "2.35", "2.39"),
    # 覆盖 Ubuntu 旧题 + LTS + 近年版本，适合扩到 1000+ 版本。
    "ubuntu-expanded": (
        "2.3",
        "2.4",
        "2.6",
        "2.7",
        "2.8",
        "2.9",
        "2.10",
        "2.11",
        "2.12",
        "2.13",
        "2.15",
        "2.17",
        "2.18",
        "2.19",
        "2.21",
        "2.23",
        "2.24",
        "2.26",
        "2.27",
        "2.28",
        "2.29",
        "2.30",
        "2.31",
        "2.32",
        "2.33",
        "2.34",
        "2.35",
        "2.36",
        "2.37",
        "2.38",
        "2.39",
        "2.40",
        "2.41",
        "2.42",
        "2.43",
    ),
}

SOURCE_POOLS: tuple[tuple[str, str], ...] = (
    ("security-eglibc", "https://security.ubuntu.com/ubuntu/pool/main/e/eglibc/"),
    ("security-glibc", "https://security.ubuntu.com/ubuntu/pool/main/g/glibc/"),
    ("archive-glibc", "https://archive.ubuntu.com/ubuntu/pool/main/g/glibc/"),
    ("archive-eglibc", "https://archive.ubuntu.com/ubuntu/pool/main/e/eglibc/"),
    ("old-eglibc", "https://old-releases.ubuntu.com/ubuntu/pool/main/e/eglibc/"),
    ("old-glibc", "https://old-releases.ubuntu.com/ubuntu/pool/main/g/glibc/"),
    ("ports-glibc", "https://ports.ubuntu.com/ubuntu-ports/pool/main/g/glibc/"),
)

PACKAGE_RE = re.compile(
    r"^(?P<package>libc6(?:-i386|-amd64)?)_"
    r"(?P<version>[^_]+)_"
    r"(?P<arch>amd64|amd64v3|i386|arm64)\.deb$"
)


@dataclass(frozen=True, slots=True)
class UbuntuLibcPackage:
    source_name: str
    pool_url: str
    filename: str
    package_name: str
    version: str
    arch: str

    @property
    def download_url(self) -> str:
        return urllib.parse.urljoin(f"{self.pool_url}/", self.filename)

    @property
    def package_id(self) -> str:
        return self.filename[:-4]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="定向收集 Ubuntu libc 版本。")
    parser.add_argument(
        "--raw-dir",
        type=Path,
        default=DEFAULT_RAW_DIR,
        help="libc raw 目录，默认 data/libc/raw。",
    )
    parser.add_argument(
        "--preset",
        choices=tuple(PRESET_MAJORS),
        default="ubuntu-expanded",
        help="预设的大版本集合，默认 ubuntu-expanded。",
    )
    parser.add_argument(
        "--major",
        action="append",
        default=[],
        help="额外追加 glibc 大版本前缀，如 2.23；可重复传入。",
    )
    parser.add_argument(
        "--arch",
        action="append",
        default=[],
        help="架构过滤，默认 amd64+i386；可重复传入。",
    )
    parser.add_argument(
        "--package",
        action="append",
        default=[],
        help="包名过滤，默认 libc6/libc6-i386/libc6-amd64；可重复传入。",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="最多下载多少个候选，默认不限制。",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="只输出计划，不实际下载。",
    )
    return parser


def fetch_text(url: str) -> str:
    curl = shutil.which("curl")
    if curl is not None:
        try:
            completed = subprocess.run(
                [
                    curl,
                    "-kfsSL",
                    "--connect-timeout",
                    "15",
                    "--max-time",
                    "60",
                    url,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            return completed.stdout
        except subprocess.CalledProcessError:
            pass
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "CHun-libc-collector/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read().decode("utf-8", errors="ignore")
    except URLError as exc:
        if isinstance(exc.reason, ssl.SSLCertVerificationError):
            insecure_context = ssl._create_unverified_context()
            with urllib.request.urlopen(
                request,
                timeout=30,
                context=insecure_context,
            ) as response:
                return response.read().decode("utf-8", errors="ignore")
        raise


def discover_packages(
    *,
    majors: tuple[str, ...],
    arches: tuple[str, ...],
    package_names: tuple[str, ...],
) -> list[UbuntuLibcPackage]:
    selected_by_id: dict[str, UbuntuLibcPackage] = {}
    for source_name, pool_url in SOURCE_POOLS:
        print(f"[scan] {source_name} -> {pool_url}", file=sys.stderr)
        try:
            html = fetch_text(pool_url)
        except Exception as exc:
            print(f"[skip] {source_name}: {exc}", file=sys.stderr)
            continue
        filenames = sorted(set(re.findall(r'href="([^"]+\.deb)"', html)))
        for filename in filenames:
            match = PACKAGE_RE.match(filename)
            if match is None:
                continue
            package_name = match.group("package")
            version = match.group("version")
            arch = match.group("arch")
            if package_name not in package_names:
                continue
            if arch not in arches:
                continue
            if majors and not any(version.startswith(prefix) for prefix in majors):
                continue
            package = UbuntuLibcPackage(
                source_name=source_name,
                pool_url=pool_url,
                filename=filename,
                package_name=package_name,
                version=version,
                arch=arch,
            )
            selected_by_id.setdefault(package.package_id, package)
    return sorted(
        selected_by_id.values(),
        key=lambda item: (item.version, item.package_name, item.arch, item.package_id),
    )


def existing_ids(raw_dir: Path) -> set[str]:
    db_dir = raw_dir / "db"
    if not db_dir.is_dir():
        return set()
    return {path.stem for path in db_dir.glob("*.info")}


def run_get_ubuntu(raw_dir: Path, package: UbuntuLibcPackage) -> None:
    command = (
        "cd \"$1\" && "
        ". common/libc.sh && "
        "get_ubuntu \"$2\" \"$3\""
    )
    subprocess.run(
        ["bash", "-lc", command, "--", str(raw_dir), package.download_url, package.source_name],
        check=True,
    )


def print_summary(packages: list[UbuntuLibcPackage], *, known_ids: set[str]) -> None:
    total = len(packages)
    new_packages = [pkg for pkg in packages if pkg.package_id not in known_ids]
    major_counter = Counter(pkg.version.split("-")[0] for pkg in new_packages)
    arch_counter = Counter(pkg.arch for pkg in new_packages)
    package_counter = Counter(pkg.package_name for pkg in new_packages)

    print(f"discovered={total}")
    print(f"already_present={total - len(new_packages)}")
    print(f"to_download={len(new_packages)}")
    if not new_packages:
        return
    print("by_arch=" + ", ".join(f"{arch}:{count}" for arch, count in sorted(arch_counter.items())))
    print(
        "by_package="
        + ", ".join(f"{name}:{count}" for name, count in sorted(package_counter.items()))
    )
    print(
        "by_major="
        + ", ".join(f"{major}:{count}" for major, count in sorted(major_counter.items()))
    )
    print("sample=")
    for package in new_packages[:20]:
        print(
            f"  {package.package_id} [{package.source_name}] "
            f"{package.package_name} {package.version} {package.arch}"
        )


def main() -> int:
    args = build_parser().parse_args()
    majors = tuple(dict.fromkeys((*PRESET_MAJORS[args.preset], *args.major)))
    arches = tuple(dict.fromkeys(args.arch or DEFAULT_ARCHES))
    package_names = tuple(dict.fromkeys(args.package or DEFAULT_PACKAGES))

    packages = discover_packages(
        majors=majors,
        arches=arches,
        package_names=package_names,
    )
    known_ids = existing_ids(args.raw_dir)
    print_summary(packages, known_ids=known_ids)

    to_download = [pkg for pkg in packages if pkg.package_id not in known_ids]
    if args.limit is not None:
        to_download = to_download[: args.limit]
    if args.dry_run:
        return 0

    for index, package in enumerate(to_download, start=1):
        print(
            f"[{index}/{len(to_download)}] "
            f"{package.package_id} <- {package.download_url}"
        )
        run_get_ubuntu(args.raw_dir, package)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
