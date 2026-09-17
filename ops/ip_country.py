"""Offline DB-IP Lite CSV index and bounded read-only IP country estimates.

No network, subprocess, secret access or runtime database writes. The builder
accepts an already verified local CSV/gzip download; attribution belongs in UI.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import gzip
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import stat
import tempfile
from pathlib import Path
from typing import Any, Sequence

DEFAULT_PATH = Path("/usr/local/share/monitor-collector/ip-country.sqlite")
MAX_DB_BYTES = 128 * 1024 * 1024
MAX_CSV_BYTES = 64 * 1024 * 1024
MAX_ROW_BYTES = 512
MAX_RECORDS = 1_000_000
COUNTRY = re.compile(r"[A-Z]{2}")
SCHEMA = {
    "metadata": "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID",
    "ranges": "CREATE TABLE ranges (version INTEGER NOT NULL, start BLOB NOT NULL, end BLOB NOT NULL, country TEXT NOT NULL, PRIMARY KEY (version, start), CHECK (version IN (4,6)), CHECK (length(start) = CASE version WHEN 4 THEN 4 ELSE 16 END), CHECK (length(end) = length(start)), CHECK (start <= end), CHECK (length(country) = 2)) WITHOUT ROWID",
}
META_FIELDS = {"schemaVersion", "databaseDate", "source", "license", "checksumSha256", "recordCount"}


def _date(value: str) -> dt.date:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError("invalid country database date")
    return dt.date.fromisoformat(value)


def _parent(path: Path) -> int:
    if not path.is_absolute() or path.parent.resolve() != path.parent:
        raise ValueError("unsafe country database parent")
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    info = os.fstat(descriptor)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o022:
        os.close(descriptor)
        raise ValueError("unsafe country database parent")
    return descriptor


def _file(path: Path, maximum: int) -> tuple[int, os.stat_result]:
    parent = _parent(path)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0), dir_fd=parent)
    finally:
        os.close(parent)
    info = os.fstat(descriptor)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid not in {0, os.geteuid()}
            or info.st_mode & 0o022 or not 0 < info.st_size <= maximum):
        os.close(descriptor)
        raise ValueError("unsafe country database file")
    return descriptor, info


class RuntimeCountryLookup:
    def __init__(self, path: Path | str = DEFAULT_PATH, *, today: dt.date | None = None):
        self.path = Path(path)
        self.today = today or dt.datetime.now(dt.timezone.utc).date()
        self.connection: sqlite3.Connection | None = None
        self.descriptor: int | None = None
        self.database_date: str | None = None
        self.stale = False

    def __enter__(self) -> "RuntimeCountryLookup":
        self.close()
        try:
            self.descriptor, info = _file(self.path, MAX_DB_BYTES)
            # Keep a validated descriptor alive for the lifetime of SQLite.
            # Verify the resolved DB inode before and after opening as SQLite
            # builds may canonicalize /proc/self/fd paths internally.
            uri = f"file:/proc/self/fd/{self.descriptor}?mode=ro&immutable=1"
            connection = sqlite3.connect(uri, uri=True, timeout=0)
            self.connection = connection
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA cache_size=-2048")
            connection.execute("PRAGMA mmap_size=0")
            connection.execute("PRAGMA temp_store=MEMORY")
            after = self.path.lstat()
            opened_name = connection.execute("PRAGMA database_list").fetchone()[2]
            opened = os.stat(opened_name)
            if any((item.st_dev, item.st_ino) != (info.st_dev, info.st_ino) for item in (after, opened)):
                raise ValueError("country database changed during open")
            schema = connection.execute("SELECT name,type,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 3").fetchall()
            if schema != [(name, "table", sql) for name, sql in sorted(SCHEMA.items())]:
                raise ValueError("invalid country database schema")
            metadata_rows = connection.execute("SELECT key,value FROM metadata LIMIT 7").fetchall()
            metadata = dict(metadata_rows)
            if (set(metadata) != META_FIELDS or metadata["schemaVersion"] != "1"
                    or metadata["source"] != "DB-IP IP to Country Lite" or metadata["license"] != "CC BY 4.0"
                    or not re.fullmatch(r"[0-9a-f]{64}", metadata["checksumSha256"])
                    or not re.fullmatch(r"[1-9][0-9]{0,6}", metadata["recordCount"])
                    or int(metadata["recordCount"]) > MAX_RECORDS):
                raise ValueError("invalid country database metadata")
            date = _date(metadata["databaseDate"])
            if date > self.today:
                raise ValueError("future country database date")
            self.database_date = date.isoformat()
            self.stale = (self.today - date).days > 90
        except (OSError, ValueError, TypeError, sqlite3.Error):
            self.close()
        return self

    def close(self) -> None:
        if self.connection is not None:
            self.connection.close()
        if self.descriptor is not None:
            os.close(self.descriptor)
        self.connection = None
        self.descriptor = None
        self.database_date = None
        self.stale = False

    def __exit__(self, *_args: Any) -> None:
        self.close()

    def lookup(self, value: str) -> dict[str, str | None]:
        def result(state: str, country: str | None = None) -> dict[str, str | None]:
            return {"countryCode": country, "countryStatus": state, "databaseDate": self.database_date}
        try:
            if not isinstance(value, str) or len(value) > 64 or "%" in value:
                return result("unavailable")
            address = ipaddress.ip_address(value)
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            if not address.is_global or address.is_multicast or address.is_reserved:
                return result("private")
        except ValueError:
            return result("unavailable")
        if self.connection is None:
            return result("unavailable")
        try:
            row = self.connection.execute(
                "SELECT end,country FROM ranges WHERE version=? AND start<=? ORDER BY start DESC LIMIT 1",
                (address.version, address.packed),
            ).fetchone()
            if row is None:
                return result("stale" if self.stale else "not_found")
            end, country = row
            if not isinstance(end, bytes) or len(end) != len(address.packed) or not isinstance(country, str) or COUNTRY.fullmatch(country) is None:
                return result("unavailable")
            if address.packed > end:
                return result("stale" if self.stale else "not_found")
            if country == "ZZ":
                # DB-IP's unknown-region marker is not an estimated country.
                return result("stale" if self.stale else "not_found")
            return result("stale" if self.stale else "estimated", country)
        except sqlite3.Error:
            return result("unavailable")


CountryLookup = RuntimeCountryLookup


def build_database(input_path: Path | str, output_path: Path | str, database_date: str,
                   *, sha256: str | None = None, today: dt.date | None = None) -> dict[str, str | int]:
    """Build from a local CSV/gzip; retain the old DB until validated atomic replacement."""
    source, target = Path(input_path), Path(output_path)
    if source == target:
        raise ValueError("country database input and output must differ")
    if _date(database_date) > (today or dt.datetime.now(dt.timezone.utc).date()):
        raise ValueError("future country database date")
    if sha256 is not None and re.fullmatch(r"[0-9a-fA-F]{64}", sha256) is None:
        raise ValueError("invalid country database checksum")
    source_fd, source_info = _file(source, MAX_CSV_BYTES)
    parent_fd: int | None = None
    temporary: Path | None = None
    connection: sqlite3.Connection | None = None
    try:
        parent_fd = _parent(target)
        try:
            old_fd, _ = _file(target, MAX_DB_BYTES)
        except FileNotFoundError:
            pass
        else:
            os.close(old_fd)
        digest = hashlib.sha256()
        hashed_bytes = 0
        while chunk := os.read(source_fd, 65536):
            hashed_bytes += len(chunk)
            if hashed_bytes > MAX_CSV_BYTES:
                raise ValueError("country CSV exceeds bounds")
            digest.update(chunk)
        checksum = digest.hexdigest()
        if sha256 is not None and checksum != sha256.lower():
            raise ValueError("country database checksum mismatch")
        os.lseek(source_fd, 0, os.SEEK_SET)
        descriptor, name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
        os.close(descriptor)
        temporary = Path(name)
        connection = sqlite3.connect(temporary)
        connection.execute("PRAGMA journal_mode=OFF")
        connection.execute("PRAGMA cache_size=-2048")
        for sql in SCHEMA.values():
            connection.execute(sql)
        previous: dict[int, int] = {}
        count = total = 0
        batch = []
        is_gzip = os.pread(source_fd, 2, 0) == b"\x1f\x8b"
        with os.fdopen(os.dup(source_fd), "rb") as raw:
            stream = gzip.GzipFile(fileobj=raw) if is_gzip else raw
            try:
                while line := stream.readline(MAX_ROW_BYTES + 1):
                    total += len(line)
                    if len(line) > MAX_ROW_BYTES or total > MAX_CSV_BYTES or count >= MAX_RECORDS:
                        raise ValueError("country CSV exceeds bounds")
                    fields = next(csv.reader([line.decode("ascii")], strict=True))
                    if len(fields) != 3 or COUNTRY.fullmatch(fields[2]) is None:
                        raise ValueError("invalid country CSV row")
                    first, last = ipaddress.ip_address(fields[0]), ipaddress.ip_address(fields[1])
                    if first.version != last.version or int(first) > int(last) or int(first) <= previous.get(first.version, -1):
                        raise ValueError("unordered or overlapping country range")
                    previous[first.version] = int(last)
                    batch.append((first.version, first.packed, last.packed, fields[2]))
                    count += 1
                    if len(batch) >= 2000:
                        connection.executemany("INSERT INTO ranges VALUES (?,?,?,?)", batch)
                        batch = []
                if batch:
                    connection.executemany("INSERT INTO ranges VALUES (?,?,?,?)", batch)
            finally:
                if stream is not raw:
                    stream.close()
        after = os.fstat(source_fd)
        if not count or (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (source_info.st_size, source_info.st_mtime_ns, source_info.st_ctime_ns):
            raise ValueError("empty or changed country CSV")
        metadata = {"schemaVersion": "1", "databaseDate": database_date, "source": "DB-IP IP to Country Lite",
                    "license": "CC BY 4.0", "checksumSha256": checksum, "recordCount": str(count)}
        connection.executemany("INSERT INTO metadata VALUES (?,?)", metadata.items())
        connection.commit()
        connection.close()
        connection = None
        temporary.chmod(0o644)
        final_fd, _ = _file(temporary, MAX_DB_BYTES)
        try:
            os.fsync(final_fd)
        finally:
            os.close(final_fd)
        os.replace(temporary, target)
        temporary = None
        os.fsync(parent_fd)
        return {"records": count, "databaseDate": database_date, "checksumSha256": checksum}
    except (UnicodeError, csv.Error, EOFError, StopIteration) as error:
        raise ValueError("invalid country CSV") from error
    finally:
        if connection is not None:
            connection.close()
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        if parent_fd is not None:
            os.close(parent_fd)
        os.close(source_fd)


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build Monitor's offline DB-IP Lite country index")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--database-date", required=True)
    parser.add_argument("--sha256", help="expected SHA-256 of the supplied CSV/gzip file")
    values = parser.parse_args(arguments)
    try:
        print(json.dumps(build_database(values.input, values.output, values.database_date, sha256=values.sha256), sort_keys=True))
        return 0
    except (OSError, ValueError, sqlite3.Error):
        print(json.dumps({"status": "error", "reason": "country database build failed"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
