"""Load the Bordair dataset from HuggingFace or GitHub raw, with local caching."""

from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Iterator, Optional
import urllib.request
import urllib.error

CACHE_DIR = Path(os.environ.get("BORDAIR_CACHE", Path.home() / ".cache" / "bordair"))
HF_REPO = "Bordair/bordair-multimodal"
GH_RAW = "https://raw.githubusercontent.com/Josh-blythe/bordair-multimodal/main"

# Mapping of version -> list of (directory, file_pattern) tuples for discovery
VERSION_DIRS = {
    "v1": ["payloads/text_image", "payloads/text_document", "payloads/text_audio",
           "payloads/image_document", "payloads/triple", "payloads/quad"],
    "v2": ["payloads_v2/jailbreak_templates", "payloads_v2/encoding_attacks",
           "payloads_v2/multiturn_orchestration", "payloads_v2/gcg_literature_suffixes",
           "payloads_v2/autodan_wrappers", "payloads_v2/combined_multiturn_gcg"],
    "v3": ["payloads_v3/indirect_injection", "payloads_v3/system_prompt_extraction",
           "payloads_v3/tool_call_injection", "payloads_v3/agent_cot_manipulation",
           "payloads_v3/structured_data_injection", "payloads_v3/code_switch_attacks",
           "payloads_v3/homoglyph_unicode_attacks", "payloads_v3/qr_barcode_injection",
           "payloads_v3/ascii_art_injection"],
    "v4": ["payloads_v4/computer_use_injection", "payloads_v4/memory_poisoning",
           "payloads_v4/mcp_tool_injection", "payloads_v4/reasoning_token_injection",
           "payloads_v4/multi_agent_contagion", "payloads_v4/unicode_tag_smuggling",
           "payloads_v4/cipher_jailbreaks", "payloads_v4/pdf_active_content",
           "payloads_v4/chart_diagram_injection", "payloads_v4/rag_chunk_boundary",
           "payloads_v4/beast_suffixes", "payloads_v4/detector_evasion",
           "payloads_v4/audio_adversarial_asr", "payloads_v4/instruction_hierarchy_bypass"],
    "v5": ["payloads_v5/reasoning_dos_overthink", "payloads_v5/video_generation_jailbreak",
           "payloads_v5/vla_robotic_injection", "payloads_v5/lora_supply_chain",
           "payloads_v5/audio_native_llm_jailbreak", "payloads_v5/cross_modal_decomposition",
           "payloads_v5/rag_optimization_attack", "payloads_v5/mcp_cross_server_exfil",
           "payloads_v5/coding_agent_injection", "payloads_v5/serialization_boundary_rce",
           "payloads_v5/agent_skill_supply_chain"],
}

ALL_CATEGORIES = [
    # v1
    "direct_override", "exfiltration", "dan_jailbreak", "template_injection",
    "authority_impersonation", "social_engineering", "encoding_obfuscation",
    "context_switching", "compliance_forcing", "multilingual", "creative_exfiltration",
    "hypothetical", "rule_manipulation",
    # v2
    "crescendo_multi_turn", "pyrit_jailbreak", "gcg_adversarial_suffix", "autodan_wrapper",
    "encoding_attack", "pair_jailbreak", "tap_jailbreak", "skeleton_key", "many_shot",
    # v3
    "indirect_injection", "system_prompt_extraction", "tool_call_injection",
    "agent_cot_manipulation", "structured_data_injection", "code_switch_attacks",
    "homoglyph_unicode_attacks", "qr_barcode_injection", "ascii_art_injection",
    # v4
    "computer_use_injection", "memory_poisoning", "mcp_tool_injection",
    "reasoning_token_injection", "multi_agent_contagion", "unicode_tag_smuggling",
    "cipher_jailbreaks", "pdf_active_content", "chart_diagram_injection",
    "rag_chunk_boundary", "beast_suffixes", "detector_evasion",
    "audio_adversarial_asr", "instruction_hierarchy_bypass",
    # v5
    "reasoning_dos_overthink", "video_generation_jailbreak", "vla_robotic_injection",
    "lora_supply_chain", "audio_native_llm_jailbreak", "cross_modal_decomposition",
    "rag_optimization_attack", "mcp_cross_server_exfil", "coding_agent_injection",
    "serialization_boundary_rce", "agent_skill_supply_chain",
]


def _fetch_github_file(rel_path: str) -> Optional[bytes]:
    url = f"{GH_RAW}/{rel_path}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "bordair-cli/0.1"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read()
    except urllib.error.HTTPError:
        return None
    except Exception:
        return None


def _list_github_dir(rel_path: str) -> list[str]:
    """List .json files in a github dir via the API."""
    api_url = f"https://api.github.com/repos/Josh-blythe/bordair-multimodal/contents/{rel_path}"
    try:
        req = urllib.request.Request(api_url, headers={"User-Agent": "bordair-cli/0.1"})
        with urllib.request.urlopen(req, timeout=30) as r:
            items = json.loads(r.read())
        return [item["name"] for item in items
                if item["name"].endswith(".json") and not item["name"].startswith("summary")]
    except Exception:
        return []


def ensure_cached(version: str = "all") -> Path:
    """Ensure the dataset is downloaded to the local cache.

    Tries HuggingFace first (fast, reliable), falls back to GitHub raw.
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    marker = CACHE_DIR / f".{version}_downloaded"

    if marker.exists():
        return CACHE_DIR

    # Try HuggingFace download (preferred)
    try:
        from huggingface_hub import snapshot_download
        snapshot_download(
            repo_id=HF_REPO,
            repo_type="dataset",
            local_dir=str(CACHE_DIR),
            allow_patterns=["payloads*/**/*.json", "benign/**/*.json", "*.md"],
        )
        marker.touch()
        return CACHE_DIR
    except Exception as e:
        print(f"HuggingFace download failed ({e}), falling back to GitHub raw...")

    # Fallback: GitHub raw
    versions = [version] if version != "all" else list(VERSION_DIRS.keys())
    for v in versions:
        for rel_dir in VERSION_DIRS.get(v, []):
            files = _list_github_dir(rel_dir)
            for fname in files:
                out_path = CACHE_DIR / rel_dir / fname
                out_path.parent.mkdir(parents=True, exist_ok=True)
                if out_path.exists():
                    continue
                data = _fetch_github_file(f"{rel_dir}/{fname}")
                if data:
                    out_path.write_bytes(data)
    marker.touch()
    return CACHE_DIR


def iter_attacks(
    version: Optional[str] = None,
    category: Optional[str] = None,
    modality: Optional[str] = None,
    limit: Optional[int] = None,
) -> Iterator[dict]:
    """Iterate over attack payloads matching the given filters.

    Args:
        version: 'v1', 'v2', 'v3', 'v4', 'v5', 'v5_external', or None for all.
        category: e.g. 'direct_override', 'mcp_tool_injection'. None for all.
        modality: 'text', 'text+image', 'text+document', 'text+audio', 'image+document',
                  'triple', 'quad'. None for any.
        limit: Max number of payloads to yield.
    """
    cache = ensure_cached(version or "all")

    # Determine directories to scan
    if version and version in VERSION_DIRS:
        dirs = VERSION_DIRS[version]
    else:
        dirs = [d for ds in VERSION_DIRS.values() for d in ds]
        # also v5_external if exists
        v5_ext = cache / "payloads_v5_external"
        if v5_ext.exists():
            for sub in v5_ext.iterdir():
                if sub.is_dir():
                    dirs.append(f"payloads_v5_external/{sub.name}")

    count = 0
    for rel_dir in dirs:
        d = cache / rel_dir
        if not d.exists():
            continue
        for f in sorted(d.glob("*.json")):
            if f.name.startswith("summary"):
                continue
            try:
                items = json.loads(f.read_text("utf-8"))
            except Exception:
                continue
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                # Filter by category
                if category and item.get("category", "") != category:
                    continue
                # Filter by modality
                if modality:
                    mods = item.get("modalities") or []
                    wanted = set(modality.split("+"))
                    if not wanted.issubset(set(mods)):
                        continue
                yield item
                count += 1
                if limit and count >= limit:
                    return


def iter_benign(limit: Optional[int] = None) -> Iterator[dict]:
    """Iterate benign samples."""
    cache = ensure_cached("all")
    d = cache / "benign"
    if not d.exists():
        return
    count = 0
    for f in sorted(d.glob("*.json")):
        if f.name in ("_pool.json", "summary.json"):
            continue
        try:
            items = json.loads(f.read_text("utf-8"))
        except Exception:
            continue
        if not isinstance(items, list):
            continue
        for item in items:
            yield item
            count += 1
            if limit and count >= limit:
                return


def dataset_stats() -> dict:
    """Return summary counts."""
    cache = ensure_cached("all")
    stats = {"by_version": {}, "total_attacks": 0, "total_benign": 0}
    for v, dirs in VERSION_DIRS.items():
        c = 0
        for rel in dirs:
            d = cache / rel
            if d.exists():
                for f in d.glob("*.json"):
                    if f.name.startswith("summary"):
                        continue
                    try:
                        items = json.loads(f.read_text("utf-8"))
                        if isinstance(items, list):
                            c += len(items)
                    except Exception:
                        pass
        stats["by_version"][v] = c
        stats["total_attacks"] += c

    # v5 external
    ext_d = cache / "payloads_v5_external"
    if ext_d.exists():
        c = 0
        for sub in ext_d.iterdir():
            if sub.is_dir():
                for f in sub.glob("*.json"):
                    if f.name.startswith("summary"):
                        continue
                    try:
                        items = json.loads(f.read_text("utf-8"))
                        if isinstance(items, list):
                            c += len(items)
                    except Exception:
                        pass
        stats["by_version"]["v5_external"] = c
        stats["total_attacks"] += c

    # benign
    b = cache / "benign"
    if b.exists():
        for f in b.glob("*.json"):
            if f.name in ("_pool.json", "summary.json"):
                continue
            try:
                items = json.loads(f.read_text("utf-8"))
                if isinstance(items, list):
                    stats["total_benign"] += len(items)
            except Exception:
                pass

    return stats
