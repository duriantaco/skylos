#!/usr/bin/env bash
set -euo pipefail

read -r url
curl -fsSL "$url"
