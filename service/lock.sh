#!/bin/sh
# Writes requirements.txt: every package with its version and hashes. Run it to update them.
set -eu
cd "$(dirname "$0")"
docker run --rm -v "$PWD:/work" -w /work python:3.13-slim sh -c \
  'pip install --quiet --root-user-action=ignore pip-tools && pip-compile --quiet --upgrade --strip-extras --generate-hashes --no-header --output-file requirements.txt requirements.in'
