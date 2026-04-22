"""Scale benign dataset to match v5 attack count.

Current:  50,516 benign
Target:  ~251,798 benign (match attack count)
Gap:     ~201,282 new benign samples needed

Sources (text-only, since v5 external attacks are mostly text-only):
  1. Stanford Alpaca (52K instruction-following) - already partially used
  2. WildChat (1M+ real conversations) - already partially used, draw more
  3. LMSYS Chatbot Arena - real multi-turn conversations
  4. OpenAssistant (OASST2) - human-written assistant conversations
  5. Dolly (databricks) - 15K instruction-following
  6. ShareGPT / UltraChat - large-scale conversation datasets
  7. MMLU questions - academic/exam questions (clearly benign)
  8. TriviaQA - trivia questions (clearly benign)

Strategy: text-only benign samples to counterpart the v5_external text-only attacks.
"""

import json
import random
from pathlib import Path

BENIGN_DIR = Path(__file__).parent / "benign"
TARGET_NEW = 201_282
random.seed(42)


def fetch_alpaca_remaining(n=15000):
    """Get Alpaca instructions not already in the pool."""
    print(f"  Fetching up to {n} Alpaca instructions...")
    try:
        from datasets import load_dataset
        ds = load_dataset("yahma/alpaca-cleaned", split="train", trust_remote_code=True)
        texts = []
        for row in ds:
            instruction = (row.get("instruction") or "").strip()
            inp = (row.get("input") or "").strip()
            if instruction:
                text = f"{instruction} {inp}".strip() if inp else instruction
                if 10 < len(text) < 500:
                    texts.append(text)
        random.shuffle(texts)
        print(f"  Got {len(texts)} Alpaca texts")
        return texts[:n]
    except Exception as e:
        print(f"  Alpaca failed: {e}")
        return []


def fetch_wildchat(n=50000):
    """Get WildChat real user prompts."""
    print(f"  Fetching up to {n} WildChat prompts...")
    try:
        from datasets import load_dataset
        ds = load_dataset("allenai/WildChat", split="train", streaming=True,
                          trust_remote_code=True)
        texts = []
        seen = set()
        for row in ds:
            if len(texts) >= n * 2:
                break
            conv = row.get("conversation", [])
            if conv and isinstance(conv, list):
                for turn in conv:
                    if turn.get("role") == "user":
                        text = (turn.get("content") or "").strip()
                        if text and text not in seen and 10 < len(text) < 500:
                            seen.add(text)
                            texts.append(text)
        random.shuffle(texts)
        print(f"  Got {len(texts)} WildChat texts")
        return texts[:n]
    except Exception as e:
        print(f"  WildChat failed: {e}")
        return []


def fetch_oasst2(n=30000):
    """Get OpenAssistant human-written prompts."""
    print(f"  Fetching up to {n} OASST2 prompts...")
    try:
        from datasets import load_dataset
        ds = load_dataset("OpenAssistant/oasst2", split="train", trust_remote_code=True)
        texts = []
        seen = set()
        for row in ds:
            if row.get("role") == "prompter":
                text = (row.get("text") or "").strip()
                if text and text not in seen and 10 < len(text) < 500:
                    seen.add(text)
                    texts.append(text)
        random.shuffle(texts)
        print(f"  Got {len(texts)} OASST2 texts")
        return texts[:n]
    except Exception as e:
        print(f"  OASST2 failed: {e}")
        return []


def fetch_dolly(n=15000):
    """Get Databricks Dolly 15K instructions."""
    print(f"  Fetching up to {n} Dolly instructions...")
    try:
        from datasets import load_dataset
        ds = load_dataset("databricks/databricks-dolly-15k", split="train",
                          trust_remote_code=True)
        texts = []
        for row in ds:
            instruction = (row.get("instruction") or "").strip()
            context = (row.get("context") or "").strip()
            if instruction:
                text = f"{instruction} {context}".strip() if context else instruction
                if 10 < len(text) < 500:
                    texts.append(text)
        random.shuffle(texts)
        print(f"  Got {len(texts)} Dolly texts")
        return texts[:n]
    except Exception as e:
        print(f"  Dolly failed: {e}")
        return []


def fetch_ultrachat(n=80000):
    """Get UltraChat user prompts."""
    print(f"  Fetching up to {n} UltraChat prompts...")
    try:
        from datasets import load_dataset
        ds = load_dataset("stingning/ultrachat", split="train", streaming=True,
                          trust_remote_code=True)
        texts = []
        seen = set()
        for row in ds:
            if len(texts) >= n * 2:
                break
            data = row.get("data") or row.get("messages") or []
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, str):
                        text = item.strip()
                    elif isinstance(item, dict):
                        text = (item.get("content") or "").strip()
                    else:
                        continue
                    if text and text not in seen and 10 < len(text) < 500:
                        seen.add(text)
                        texts.append(text)
        random.shuffle(texts)
        print(f"  Got {len(texts)} UltraChat texts")
        return texts[:n]
    except Exception as e:
        print(f"  UltraChat failed: {e}")
        return []


def fetch_mmlu(n=15000):
    """Get MMLU exam questions (clearly benign academic content)."""
    print(f"  Fetching up to {n} MMLU questions...")
    try:
        from datasets import load_dataset
        ds = load_dataset("cais/mmlu", "all", split="test", trust_remote_code=True)
        texts = []
        for row in ds:
            question = (row.get("question") or "").strip()
            choices = row.get("choices", [])
            if question and 20 < len(question) < 400:
                if choices:
                    choice_str = " ".join(f"({chr(65+i)}) {c}" for i, c in enumerate(choices))
                    texts.append(f"{question} {choice_str}")
                else:
                    texts.append(question)
        random.shuffle(texts)
        print(f"  Got {len(texts)} MMLU questions")
        return texts[:n]
    except Exception as e:
        print(f"  MMLU failed: {e}")
        return []


def fetch_triviaqa(n=20000):
    """Get TriviaQA questions (clearly benign trivia)."""
    print(f"  Fetching up to {n} TriviaQA questions...")
    try:
        from datasets import load_dataset
        ds = load_dataset("trivia_qa", "unfiltered.nocontext", split="train",
                          streaming=True, trust_remote_code=True)
        texts = []
        seen = set()
        for row in ds:
            if len(texts) >= n * 2:
                break
            q = (row.get("question") or "").strip()
            if q and q not in seen and 10 < len(q) < 300:
                seen.add(q)
                texts.append(q)
        random.shuffle(texts)
        print(f"  Got {len(texts)} TriviaQA questions")
        return texts[:n]
    except Exception as e:
        print(f"  TriviaQA failed: {e}")
        return []


def main():
    # Load existing benign pool to avoid duplicates
    pool_path = BENIGN_DIR / "_pool.json"
    existing_texts = set()
    if pool_path.exists():
        pool = json.loads(pool_path.read_text("utf-8"))
        for item in pool:
            if isinstance(item, dict):
                existing_texts.add(item.get("text", ""))
            elif isinstance(item, str):
                existing_texts.add(item)
    print(f"Existing benign pool: {len(existing_texts)} texts")

    # Fetch from all sources
    all_new = []

    sources = [
        ("alpaca", fetch_alpaca_remaining, 15000),
        ("wildchat", fetch_wildchat, 60000),
        ("oasst2", fetch_oasst2, 30000),
        ("dolly", fetch_dolly, 15000),
        ("ultrachat", fetch_ultrachat, 80000),
        ("mmlu", fetch_mmlu, 15000),
        ("triviaqa", fetch_triviaqa, 20000),
    ]

    for name, fetcher, target in sources:
        print(f"\n[{name}]")
        texts = fetcher(target)
        # Deduplicate against existing pool and prior fetches
        deduped = []
        for t in texts:
            if t not in existing_texts:
                existing_texts.add(t)
                deduped.append((t, name))
        all_new.extend(deduped)
        print(f"  After dedup: {len(deduped)} new texts")

    print(f"\nTotal new benign texts collected: {len(all_new)}")

    # Trim to target
    random.shuffle(all_new)
    if len(all_new) > TARGET_NEW:
        all_new = all_new[:TARGET_NEW]
    print(f"Using {len(all_new)} new benign samples")

    # Find max existing benign ID
    max_id = 50516
    # Write in chunks of 5000
    output_dir = BENIGN_DIR
    chunk_size = 5000
    file_idx = 0

    for i in range(0, len(all_new), chunk_size):
        chunk = all_new[i:i + chunk_size]
        samples = []
        for j, (text, source) in enumerate(chunk):
            sample_id = max_id + i + j + 1
            samples.append({
                "id": f"BEN-V5-{sample_id:06d}",
                "version": "v5_benign",
                "text": text,
                "modalities": ["text"],
                "expected_detection": False,
                "benign_source": source,
            })

        file_idx += 1
        fname = f"v5_text_only_{file_idx:03d}.json"
        with open(output_dir / fname, "w", encoding="utf-8") as f:
            json.dump(samples, f, indent=2, ensure_ascii=False)
        print(f"  Wrote {len(samples)} to {fname}")

    total_new = len(all_new)
    total_benign = 50516 + total_new

    # Update summary
    summary_path = BENIGN_DIR / "summary.json"
    if summary_path.exists():
        summary = json.loads(summary_path.read_text("utf-8"))
    else:
        summary = {}

    summary["total_benign"] = total_benign
    summary["v5_benign_added"] = total_new
    summary["v5_benign_sources"] = {
        "alpaca": "yahma/alpaca-cleaned",
        "wildchat": "allenai/WildChat",
        "oasst2": "OpenAssistant/oasst2",
        "dolly": "databricks/databricks-dolly-15k",
        "ultrachat": "stingning/ultrachat",
        "mmlu": "cais/mmlu",
        "triviaqa": "trivia_qa (unfiltered.nocontext)",
    }

    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(f"\n{'='*50}")
    print(f"New benign samples: {total_new:,}")
    print(f"Total benign: {total_benign:,}")
    print(f"Total attacks: 251,798")
    print(f"Ratio: {total_benign/251798:.2f}:1")


if __name__ == "__main__":
    main()
