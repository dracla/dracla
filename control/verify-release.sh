#!/bin/sh
# This launcher comes from the digest-pinned bootstrap, never the wheel.
set -eu
exec /usr/local/bin/python -I /opt/dracla/verify_release.py "$@"
