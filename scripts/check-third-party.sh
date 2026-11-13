#!/usr/bin/env bash
# Prüft, ob die Modul-Tabellen in THIRD_PARTY.md zum aktuellen Stand von go.mod passen.
#   - "In der Binary enthaltene Module": genau die Module, die für Windows, Linux oder macOS
#     in die Binary kompiliert werden, jeweils mit der verwendeten Version
#   - "Nur für Tests": Version jedes gelisteten Moduls wie in go.mod
# Exit-Code 1 bei Abweichungen. Aufruf aus dem Repo-Wurzelverzeichnis.
set -euo pipefail

doc=THIRD_PARTY.md
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Tabellenzeilen eines Abschnitts als "modul version" ausgeben
table_rows() {
  awk -v section="$1" '
    /^## / { in_section = (index($0, section) > 0); next }
    in_section && /^\| \[/ {
      split($0, cols, "|")
      mod = cols[2]; sub(/^ *\[/, "", mod); sub(/\].*/, "", mod)
      ver = cols[3]; gsub(/ /, "", ver)
      print mod, ver
    }' "$doc" | sort
}

# Module aller Zielplattformen, die tatsächlich kompiliert werden
for os in windows linux darwin; do
  GOOS=$os go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}}{{end}}{{end}}' .
done | sort -u > "$tmp/binary_actual"
table_rows "In der Binary enthaltene Module" > "$tmp/binary_doc"

status=0
if ! diff -u "$tmp/binary_doc" "$tmp/binary_actual" > "$tmp/binary_diff"; then
  echo "FEHLER: Tabelle 'In der Binary enthaltene Module' in $doc passt nicht zu go.mod"
  echo "(- = steht in $doc, + = wird tatsächlich eingebaut)"
  tail -n +3 "$tmp/binary_diff" | grep '^[-+]'
  status=1
fi

# Test-Module: Version aus go.mod vergleichen
table_rows "Nur für Tests" > "$tmp/test_doc"
while read -r mod ver; do
  actual=$(go list -m -f '{{.Version}}' "$mod" 2>/dev/null || echo "fehlt")
  if [ "$actual" != "$ver" ]; then
    echo "FEHLER: $mod steht in $doc mit $ver, go.mod hat $actual"
    status=1
  fi
done < "$tmp/test_doc"

if [ "$status" -eq 0 ]; then
  echo "$doc ist aktuell ($(wc -l < "$tmp/binary_actual" | tr -d ' ') Module in der Binary, $(wc -l < "$tmp/test_doc" | tr -d ' ') Test-Module)"
else
  echo
  echo "Bitte $doc anpassen (Version, Lizenz und Zweck neuer Module eintragen, entfallene entfernen)."
fi
exit "$status"
