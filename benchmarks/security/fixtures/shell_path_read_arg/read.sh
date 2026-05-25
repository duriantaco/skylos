#!/usr/bin/env bash
set -euo pipefail

backup_name="$1"
cat "/srv/backups/$backup_name"
