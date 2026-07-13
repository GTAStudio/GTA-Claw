#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if command -v python >/dev/null 2>&1; then
  python "$script_dir/validate.py"
else
  python3 "$script_dir/validate.py"
fi
