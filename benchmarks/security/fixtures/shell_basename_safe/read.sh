#!/usr/bin/env bash
set -euo pipefail

backup_name="$(basename -- "$1")"
cat "/srv/backups/$backup_name"
