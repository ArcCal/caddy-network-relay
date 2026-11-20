#!/usr/bin/env bash
# Each query has one exact module version. A review for a different fork
# cannot approve this fork, even when an advisory affects both versions.
set -euo pipefail
manifest="$(dirname "$0")/provenance.json"
snapshots=$(jq -ce '.snapshots | if type == "array" and length > 0 then .[] else error("No pinned snapshots") end' "$manifest")
while IFS= read -r snapshot; do
    query=$(jq -er '[.module, .version] | if all(.[]; type == "string" and length > 0) then join("@") else error("Invalid pinned snapshot") end' <<< "$snapshot")
    reviewed=$(jq -ce '(.reviewed_advisories // {}) | keys' <<< "$snapshot")
    go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 -mode=query -json "$query" |
        jq -ser --arg query "$query" --argjson reviewed "$reviewed" '
          if any(.[]; has("config")) then . else error("Missing govulncheck output for " + $query) end
          | [.[] | select(has("osv")) | .osv.id] | unique as $found
          | ($found - $reviewed) as $unknown
          | if ($unknown | length) == 0 then "\($query) has \($found | length) reviewed advisories"
            else error($query + " has unreviewed advisories " + ($unknown | join(", "))) end'
done <<< "$snapshots"
