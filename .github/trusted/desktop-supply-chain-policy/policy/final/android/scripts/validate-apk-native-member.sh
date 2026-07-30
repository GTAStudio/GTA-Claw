#!/usr/bin/env bash
set -euo pipefail

apk="${1:?usage: validate-apk-native-member.sh <apk> <exact-member>}"
expected="${2:?usage: validate-apk-native-member.sh <apk> <exact-member>}"

if [[ ! -f "$apk" ]]; then
  echo "APK does not exist: $apk" >&2
  exit 1
fi

matches=0
while IFS= read -r member; do
  if [[ "$member" == "$expected" ]]; then
    matches=$((matches + 1))
  fi
done < <(unzip -Z1 "$apk")

if [[ "$matches" -ne 1 ]]; then
  echo "APK must contain exactly one member named $expected; found $matches" >&2
  unzip -Z1 "$apk" >&2
  exit 1
fi
