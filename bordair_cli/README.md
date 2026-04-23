# Bordair CLI

Test any LLM against the Bordair multimodal prompt injection dataset - 503,358 labeled samples from 40+ academic papers, CVE reports, and competition datasets.

## Install

One-liner:

```bash
curl -sSL https://bordair.io/install.sh | bash
```

Or with pip:

```bash
pip install bordair
```

## Quickstart

```bash
# Check dataset stats
bordair stats

# Run 100 text-only attacks against GPT-4o-mini
bordair eval \
  --url https://api.openai.com/v1/chat/completions \
  --key $OPENAI_API_KEY \
  --model gpt-4o-mini \
  --limit 100 \
  --parallel 10

# Test a local Ollama instance
bordair eval \
  --url http://localhost:11434/v1/chat/completions \
  --key ollama \
  --model llama3.1 \
  --modality text \
  --category direct_override \
  --limit 50

# Test Anthropic's native API
bordair eval \
  --url https://api.anthropic.com/v1/messages \
  --key $ANTHROPIC_API_KEY \
  --model claude-sonnet-4-5 \
  --provider anthropic \
  --limit 100

# Include benign samples to measure false-positive rate
bordair eval \
  --url https://api.openai.com/v1/chat/completions \
  --key $OPENAI_API_KEY \
  --model gpt-4o-mini \
  --include-benign \
  --limit 100 \
  --output results.json

# Compare two runs
bordair compare results_before.json results_after.json
```

## Options

```
--url              API endpoint URL (OpenAI-compatible by default)
--key              API key (or set BORDAIR_API_KEY)
--model            Model name (gpt-4o-mini, claude-sonnet-4-5, llama3.1, etc.)
--provider         openai | anthropic (default: openai)
--modality         text, text+image, text+document, text+audio, triple, etc.
--category         Filter to specific attack category (see `bordair list categories`)
--version          Filter to v1, v2, v3, v4, or v5
--limit            Max payloads to test (default: 100)
--parallel         Concurrent requests (default: 10)
--timeout          Request timeout in seconds (default: 60)
--max-tokens       Max response tokens (default: 512)
--system-prompt    Optional system prompt (tests application-layer injection)
--include-benign   Run benign samples to measure false-positive rate
--output           Write full results JSON to this path
```

## What it does

1. Downloads the dataset from HuggingFace on first run (~50MB, cached at `~/.cache/bordair/`)
2. Sends the selected attack payloads to your target LLM endpoint with the specified parallelism
3. Judges each response using category-specific heuristics (compliance prefix, system prompt leak, exfiltration URL echo, tool call patterns, etc.)
4. Reports Attack Success Rate (ASR) by category
5. Optionally measures false-positive rate on benign samples

## Supported providers

Any OpenAI-compatible API works out of the box:

- OpenAI (`https://api.openai.com/v1/chat/completions`)
- Anthropic via OpenAI-compatible shim, or use `--provider anthropic` for native API
- Azure OpenAI
- Groq (`https://api.groq.com/openai/v1/chat/completions`)
- Together AI
- Fireworks
- Ollama (`http://localhost:11434/v1/chat/completions`)
- LM Studio (`http://localhost:1234/v1/chat/completions`)
- vLLM
- Any other OpenAI-compatible endpoint

## Categories

55+ attack categories across 5 versions. See full list:

```bash
bordair list categories
```

Highlights:
- **v1**: direct override, exfiltration, DAN jailbreak, authority impersonation, encoding obfuscation
- **v2**: GCG adversarial suffixes, AutoDAN, Crescendo multi-turn, PAIR, TAP, Skeleton Key
- **v3**: indirect injection, tool call injection, homoglyph/unicode, code-switch, ASCII art
- **v4**: computer use injection, memory poisoning, MCP tool injection, reasoning token injection, BEAST suffixes
- **v5**: reasoning DoS, video generation jailbreak, VLA robotic, LoRA supply chain, audio-native LLM, serialization boundary RCE (CVE-2025-68664)

## Dataset

- HuggingFace: https://huggingface.co/datasets/Bordair/bordair-multimodal
- GitHub: https://github.com/Josh-blythe/bordair-multimodal

## License

MIT
