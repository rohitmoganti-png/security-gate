#!/usr/bin/env python3
"""Check that the current AWS credentials can call Claude on Amazon Bedrock.

Uses the standard AWS credential chain: AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY /
AWS_SESSION_TOKEN (temporary keys), a profile, or a role, and sends ONE tiny prompt.

Two Bedrock endpoints (they need DIFFERENT IAM permissions):
  --api mantle   newer "Claude in Amazon Bedrock" endpoint (Opus 5, Sonnet 5, ...)
                 IAM action: bedrock-mantle:CreateInference
  --api runtime  older bedrock-runtime InvokeModel endpoint (Sonnet 4.6, Opus 4.6, Haiku 4.5, ...)
                 IAM action: bedrock:InvokeModel ; model IDs like global.anthropic.claude-sonnet-4-6

Usage:
    export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
    python scripts/check-bedrock.py --api mantle  --model anthropic.claude-opus-5
    python scripts/check-bedrock.py --api runtime --model global.anthropic.claude-sonnet-4-6
"""

from __future__ import annotations

import argparse
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--api", choices=["mantle", "runtime"], default="mantle")
    parser.add_argument("--model", default=None, help="default depends on --api")
    args = parser.parse_args()
    args.model = args.model or (
        "anthropic.claude-opus-5" if args.api == "mantle" else "global.anthropic.claude-sonnet-4-6"
    )

    try:
        import anthropic
        from anthropic import AnthropicBedrock, AnthropicBedrockMantle
    except ImportError:
        print('Missing SDK: pip install "anthropic[bedrock]"')
        return 2

    client_cls = AnthropicBedrockMantle if args.api == "mantle" else AnthropicBedrock
    client = client_cls(aws_region=args.region)
    print(f"Calling {args.model} in {args.region} via the {args.api} endpoint ...")
    try:
        msg = client.messages.create(
            model=args.model,
            max_tokens=512,
            messages=[{"role": "user", "content": "Reply with exactly: BEDROCK OK"}],
        )
    except anthropic.AuthenticationError as exc:
        print(f"FAILED: credentials rejected (expired or invalid keys?)\n  {exc}")
        return 1
    except anthropic.PermissionDeniedError as exc:
        print(f"FAILED: access denied. Your identity may not call this model (IAM/SCP), "
              f"or the Anthropic use-case form is needed.\n  {exc}")  # fmt: skip
        return 1
    except anthropic.NotFoundError as exc:
        print(f"FAILED: model or endpoint not found. Check --model and --region.\n  {exc}")
        return 1
    except anthropic.APIStatusError as exc:
        print(f"FAILED: Bedrock returned HTTP {exc.status_code}.\n  {exc}")
        return 1
    except anthropic.APIConnectionError as exc:
        print(f"FAILED: could not reach Bedrock in {args.region}.\n  {exc}")
        return 1
    except Exception as exc:  # e.g. no credentials found at all
        print(f"FAILED: {type(exc).__name__}: {exc}")
        return 1

    text = "".join(b.text for b in msg.content if b.type == "text").strip()
    print(f"SUCCESS: Claude replied: {text!r}")
    print(f"  tokens: {msg.usage.input_tokens} in / {msg.usage.output_tokens} out | stop: {msg.stop_reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
