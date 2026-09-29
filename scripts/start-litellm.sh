#!/usr/bin/env bash
# Start LiteLLM in the background on 127.0.0.1:4000 and wait until it answers.
#
# Inputs (environment):
#   AWS_REGION                   default us-east-1
#   SECURITY_GATE_PRIMARY_MODEL  default global.anthropic.claude-sonnet-4-6
#   SECURITY_GATE_FALLBACK_MODEL default us.anthropic.claude-haiku-4-5-20251001-v1:0
#   REPORTS_BUCKET               optional; without it, S3 logging is switched off
#   LITELLM_CONFIG               default /opt/security-gate/litellm-config.yaml
# Output: LITELLM_API_KEY (a random per-run key) and LITELLM_BASE_URL, written to $GITHUB_ENV
# (masked in the log) or printed as `export` lines when run outside GitHub Actions.
# LiteLLM's own log: /tmp/litellm/litellm.log
set -euo pipefail

export AWS_REGION="${AWS_REGION:-us-east-1}"
export LITELLM_PRIMARY_MODEL="bedrock/${SECURITY_GATE_PRIMARY_MODEL:-global.anthropic.claude-sonnet-4-6}"
export LITELLM_FALLBACK_MODEL="bedrock/${SECURITY_GATE_FALLBACK_MODEL:-us.anthropic.claude-haiku-4-5-20251001-v1:0}"
export LITELLM_MASTER_KEY="sk-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export LITELLM_TELEMETRY=False
# Upload each S3 log record right away. This LiteLLM version reads these ONLY from the environment
# (s3_batch_size / s3_flush_interval in the config are ignored); the defaults (512 records / every
# 10 s) lose records, because the machine is deleted seconds after the last AI call.
export DEFAULT_S3_BATCH_SIZE=1
export DEFAULT_S3_FLUSH_INTERVAL_SECONDS=1
CONFIG="${LITELLM_CONFIG:-/opt/security-gate/litellm-config.yaml}"
PY=/opt/litellm/venv/bin/python
URL=http://127.0.0.1:4000

mkdir -p /tmp/litellm
# Effective config: same file, minus the S3 logging block when there is no bucket to write to.
"$PY" - "$CONFIG" /tmp/litellm/config.yaml <<'EOF'
import os, sys, yaml
config = yaml.safe_load(open(sys.argv[1]))
if not os.environ.get("REPORTS_BUCKET"):
    settings = config.get("litellm_settings", {})
    settings.pop("s3_callback_params", None)
    settings["callbacks"] = [c for c in settings.get("callbacks", []) if c != "s3_v2"]
    print("REPORTS_BUCKET not set: LiteLLM S3 logging is off")
yaml.safe_dump(config, open(sys.argv[2], "w"), sort_keys=False)
EOF

nohup litellm --config /tmp/litellm/config.yaml --host 127.0.0.1 --port 4000 --telemetry False \
  > /tmp/litellm/litellm.log 2>&1 &
echo $! > /tmp/litellm/pid

for _ in $(seq 1 90); do
  if curl -fsS "$URL/health/liveliness" >/dev/null 2>&1; then
    echo "LiteLLM is up on $URL (primary ${LITELLM_PRIMARY_MODEL#bedrock/}, fallback ${LITELLM_FALLBACK_MODEL#bedrock/})"
    if [[ -n "${GITHUB_ENV:-}" ]]; then
      echo "::add-mask::$LITELLM_MASTER_KEY"
      { echo "LITELLM_API_KEY=$LITELLM_MASTER_KEY"; echo "LITELLM_BASE_URL=$URL"; } >> "$GITHUB_ENV"
    else
      echo "export LITELLM_API_KEY=$LITELLM_MASTER_KEY LITELLM_BASE_URL=$URL"
    fi
    exit 0
  fi
  if ! kill -0 "$(cat /tmp/litellm/pid)" 2>/dev/null; then break; fi  # it crashed; stop waiting
  sleep 1
done

echo "LiteLLM did not start. Last lines of its log:" >&2
tail -n 40 /tmp/litellm/litellm.log >&2
exit 1
