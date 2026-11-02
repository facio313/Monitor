"""Avoid replacing the web image for reviewed host-notification-only changes.

All CI validation and image publication still run. A single-parent push is
required so a shallow checkout can prove the complete pushed change set.
Unknown paths, multi-commit pushes, and manual runs keep normal deployment.
"""

import argparse
import subprocess


HOST_NOTIFICATION_FILES = frozenset({
    ".github/workflows/deploy.yml",
    "ops/deployment_scope.py",
    "ops/notification_reports.py",
    "ops/tests/test_deployment_scope.py",
    "ops/tests/test_ssh_login_mail_policy.py",
    "docs/ai/ssh-mail-off-20261102.md",
})


def requires_runtime_deployment(event, before, parent, changed):
    return not (
        event == "push" and before and before == parent and changed
        and set(changed).issubset(HOST_NOTIFICATION_FILES)
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event", required=True)
    parser.add_argument("--before", default="")
    args = parser.parse_args()
    parent = subprocess.run(
        ["git", "rev-parse", "HEAD^"], capture_output=True, text=True, check=False,
    )
    if parent.returncode:
        print("true")
        return
    changed = subprocess.run(
        ["git", "diff", "--no-renames", "--name-only", "-z", "HEAD^", "HEAD"],
        capture_output=True, check=True,
    ).stdout.decode().split("\0")
    deploy = requires_runtime_deployment(
        args.event, args.before, parent.stdout.strip(), [path for path in changed if path],
    )
    print("true" if deploy else "false")


if __name__ == "__main__":
    main()
