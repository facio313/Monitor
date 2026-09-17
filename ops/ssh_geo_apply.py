#!/usr/bin/python3
"""Apply only the root-owned, pinned Monitor SSH country policy atomically."""
from __future__ import annotations

import argparse
import fcntl
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import urllib.request

POLICY = Path('/etc/monitor/ssh-kr-only.nft')
RUNTIME = Path('/run/monitor-ssh-geo')
TABLE = 'monitor_ssh_geo'
MAX_BYTES = 2 * 1024 * 1024
GITHUB_META_URL = 'https://api.github.com/meta'


def github_helpers():
    if __package__:
        from .github_ssh_ranges import parse_meta, render_policy
    else:
        # The privileged installed command imports only this root-owned library.
        sys.path.insert(0, '/usr/local/lib/monitor-ssh-geo')
        from github_ssh_ranges import parse_meta, render_policy
    return parse_meta, render_policy


def fetch_github_meta() -> bytes:
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise ValueError('GitHub metadata redirects are not accepted')

    request = urllib.request.Request(GITHUB_META_URL, headers={
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'monitor-ssh-github-allowlist',
        'X-GitHub-Api-Version': '2026-03-10',
    })
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=20) as response:
        if response.status != 200 or response.geturl() != GITHUB_META_URL:
            raise ValueError('unexpected GitHub metadata response')
        payload = response.read(MAX_BYTES + 1)
    if not payload or len(payload) > MAX_BYTES:
        raise ValueError('GitHub metadata exceeds bounds')
    return payload


def write_atomic(path: Path, content: str) -> None:
    descriptor, name = tempfile.mkstemp(prefix=f'.{path.name}.', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, 'w', encoding='ascii') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def run_nft(transaction: str, *, check: bool = False) -> None:
    command = ['/usr/sbin/nft'] + (['--check'] if check else []) + ['--file', '-']
    subprocess.run(command, input=transaction, text=True, check=True,
                   timeout=20, capture_output=True)


def update_policy(original: str, candidate: str, *, check: bool = False) -> bool:
    """Caller holds apply.lock. Persist and activate only a validated transaction."""
    transaction = make_transaction(candidate)
    run_nft(transaction, check=True)
    if check or candidate == original:
        return False
    write_atomic(POLICY.with_name(POLICY.name + '.previous'), original)
    try:
        write_atomic(POLICY, candidate)
        run_nft(transaction)
    except (OSError, subprocess.SubprocessError):
        # A timed-out nft process might have committed. Restore both disk and
        # the dedicated running table before reporting a recoverable failure.
        recovery_errors = []
        try:
            write_atomic(POLICY, original)
        except OSError as error:
            recovery_errors.append(error)
        try:
            run_nft(make_transaction(original))
        except (OSError, subprocess.SubprocessError) as error:
            recovery_errors.append(error)
        if recovery_errors:
            raise RuntimeError('GitHub SSH policy recovery failed; inspect saved policy and firewall') from recovery_errors[0]
        raise
    return True


def make_transaction(policy: str) -> str:
    """No includes, other tables, or top-level mutation commands are allowed."""
    body = '\n'.join(line for line in policy.splitlines() if not line.lstrip().startswith('#'))
    if (len(policy.encode('utf-8')) > MAX_BYTES
            or not re.match(r'\s*table inet monitor_ssh_geo\s*\{', body)
            or len(re.findall(r'\btable\b', body)) != 1
            or re.search(r'\b(include|flush|delete|destroy|add|create|define|import|export)\b', body)
            or not body.rstrip().endswith('}')):
        raise ValueError('policy is outside the dedicated SSH table')
    lexical = re.sub(r'"(?:[^"\\]|\\.)*"', '""', body).strip()
    depth = 0
    opened = False
    for index, character in enumerate(lexical):
        if character == '{':
            depth += 1
            opened = True
        elif character == '}':
            depth -= 1
            if depth < 0 or depth == 0 and index != len(lexical) - 1:
                raise ValueError('commands outside the dedicated SSH table')
    if not opened or depth:
        raise ValueError('unbalanced policy')
    # "add" is idempotent. The placeholder/delete/recreate is ONE netlink
    # transaction, never a separate deletion or global ruleset flush.
    return f'add table inet {TABLE}\ndelete table inet {TABLE}\n{policy}'


def read_policy() -> str:
    if POLICY.parent.resolve() != POLICY.parent:
        raise ValueError('unsafe policy directory')
    parent = POLICY.parent.stat()
    if parent.st_uid != 0 or parent.st_mode & 0o022:
        raise ValueError('unsafe policy directory')
    descriptor = os.open(POLICY, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_nlink != 1 or info.st_mode & 0o022
                or not 0 < info.st_size <= MAX_BYTES):
            raise ValueError('unsafe policy file')
        data = b''
        while chunk := os.read(descriptor, min(65536, MAX_BYTES + 1 - len(data))):
            data += chunk
            if len(data) > MAX_BYTES:
                raise ValueError('policy too large')
        return data.decode('ascii')
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='validate without changing the firewall')
    parser.add_argument('--update-github', action='store_true',
                        help='refresh all official GitHub IP exceptions, preserving the country policy')
    options = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise ValueError('root required')
        RUNTIME.mkdir(mode=0o700, exist_ok=True)
        info = RUNTIME.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('unsafe runtime directory')
        lock = os.open(RUNTIME / 'apply.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(lock)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022:
                raise ValueError('unsafe lock file')
            fcntl.flock(lock, fcntl.LOCK_EX)
            # Snapshot after acquiring the lock, so an older concurrent reader
            # cannot apply stale policy after a newer reload has completed.
            original = read_policy()
            if options.update_github:
                parse_meta, render_policy = github_helpers()
                ranges = parse_meta(fetch_github_meta())
                candidate = render_policy(original, ranges)
                changed = update_policy(original, candidate, check=options.check)
                status = 'validated' if options.check else ('applied' if changed else 'already current')
                print(f'GitHub SSH exceptions {status}; IPv4={len(ranges[4])}; IPv6={len(ranges[6])}')
            else:
                transaction = make_transaction(original)
                run_nft(transaction, check=True)
                if not options.check:
                    run_nft(transaction)
        finally:
            os.close(lock)
        if not options.update_github:
            print('Monitor SSH country policy ' + ('validated' if options.check else 'applied'))
        return 0
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        print('Monitor SSH country policy failed; existing rules retained', file=sys.stderr)
        return 1
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
