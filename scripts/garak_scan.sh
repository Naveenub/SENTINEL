#!/usr/bin/env bash
# Run garak against a model, directly or through SENTINEL, to measure what the gateway adds.
#   scripts/garak_scan.sh proxy  <model> [spec]    # via SENTINEL (needs SENTINEL_UPSTREAM_URL set on the gateway)
#   scripts/garak_scan.sh direct <model> [spec]    # straight to the upstream (baseline)
# Run the gateway with SENTINEL_PROXY_BLOCK_MODE=refusal so blocks look like model refusals to garak
# (in the default "error" mode garak sees HTTP 403 and aborts the probe).
# Compare the two reports: the difference is what SENTINEL blocks. Requires: pip install garak
set -euo pipefail
mode=${1:?proxy|direct}; model=${2:?model name}
spec=${3:-probes.promptinject,probes.encoding,probes.latentinjection,probes.dan}
case "$mode" in
  proxy)  uri="${SENTINEL_GATEWAY:-http://127.0.0.1:8080}/proxy/garak-target/v1/"; key="unused" ;;
  direct) uri="${UPSTREAM_URI:?set UPSTREAM_URI, e.g. https://api.openai.com/v1/}"; key="${UPSTREAM_KEY:?set UPSTREAM_KEY}" ;;
  *) echo "mode must be proxy or direct" >&2; exit 2 ;;
esac
export OPENAICOMPATIBLE_API_KEY="$key"
exec python -m garak \
  --target_type openai.OpenAICompatible --target_name "$model" \
  --generator_options "{\"openai\":{\"OpenAICompatible\":{\"uri\":\"$uri\"}}}" \
  --spec "$spec" --report_prefix "garak_${mode}"
