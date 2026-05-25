#!/usr/bin/env bash
set -euo pipefail

artifact="$1"
curl -fsSL "https://downloads.example.com/releases/$artifact"
