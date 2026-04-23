"""Async evaluation engine - sends attack payloads to a target LLM endpoint."""

from __future__ import annotations
import asyncio
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Optional, Iterable, Callable
import httpx

from .judge import judge_response, JudgeResult


@dataclass
class EvalRequest:
    payload_id: str
    category: str
    text: str
    version: str = ""
    modalities: list = field(default_factory=list)
    extra: dict = field(default_factory=dict)


@dataclass
class EvalResult:
    payload_id: str
    category: str
    version: str
    request_text: str
    response_text: str
    attack_succeeded: bool
    confidence: float
    judge_reason: str
    latency_ms: int
    status_code: int = 200
    error: Optional[str] = None


async def _call_openai_compatible(
    client: httpx.AsyncClient,
    url: str,
    key: str,
    model: str,
    system_prompt: str,
    user_text: str,
    timeout: float = 60.0,
    max_tokens: int = 512,
) -> tuple[str, int, Optional[str]]:
    """Send a single chat completion request to an OpenAI-compatible endpoint."""
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {key}",
    }
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": user_text})

    body = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": 0.0,
    }
    try:
        r = await client.post(url, headers=headers, json=body, timeout=timeout)
        if r.status_code != 200:
            return "", r.status_code, f"HTTP {r.status_code}: {r.text[:200]}"
        data = r.json()
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        return content or "", 200, None
    except httpx.TimeoutException:
        return "", 408, "timeout"
    except Exception as e:
        return "", 500, f"{type(e).__name__}: {e}"


async def _call_anthropic(
    client: httpx.AsyncClient,
    url: str,
    key: str,
    model: str,
    system_prompt: str,
    user_text: str,
    timeout: float = 60.0,
    max_tokens: int = 512,
) -> tuple[str, int, Optional[str]]:
    """Send a single request to Anthropic's native API."""
    headers = {
        "Content-Type": "application/json",
        "x-api-key": key,
        "anthropic-version": "2023-06-01",
    }
    body = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": user_text}],
    }
    if system_prompt:
        body["system"] = system_prompt
    try:
        r = await client.post(url, headers=headers, json=body, timeout=timeout)
        if r.status_code != 200:
            return "", r.status_code, f"HTTP {r.status_code}: {r.text[:200]}"
        data = r.json()
        blocks = data.get("content", [])
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        return text, 200, None
    except httpx.TimeoutException:
        return "", 408, "timeout"
    except Exception as e:
        return "", 500, f"{type(e).__name__}: {e}"


async def _run_single(
    client: httpx.AsyncClient,
    req: EvalRequest,
    url: str,
    key: str,
    model: str,
    provider: str,
    system_prompt: str,
    timeout: float,
    max_tokens: int,
    semaphore: asyncio.Semaphore,
    on_done: Optional[Callable[[EvalResult], None]] = None,
) -> EvalResult:
    async with semaphore:
        t0 = time.time()
        if provider == "anthropic":
            response, status, err = await _call_anthropic(
                client, url, key, model, system_prompt, req.text, timeout, max_tokens
            )
        else:
            response, status, err = await _call_openai_compatible(
                client, url, key, model, system_prompt, req.text, timeout, max_tokens
            )
        latency_ms = int((time.time() - t0) * 1000)

        if err:
            result = EvalResult(
                payload_id=req.payload_id,
                category=req.category,
                version=req.version,
                request_text=req.text,
                response_text=response,
                attack_succeeded=False,
                confidence=0.0,
                judge_reason=f"error: {err}",
                latency_ms=latency_ms,
                status_code=status,
                error=err,
            )
        else:
            jr: JudgeResult = judge_response(
                response, req.category, req.text, req.extra
            )
            result = EvalResult(
                payload_id=req.payload_id,
                category=req.category,
                version=req.version,
                request_text=req.text,
                response_text=response,
                attack_succeeded=jr.attack_succeeded,
                confidence=jr.confidence,
                judge_reason=jr.reason,
                latency_ms=latency_ms,
                status_code=status,
            )

        if on_done:
            on_done(result)
        return result


async def evaluate(
    requests: Iterable[EvalRequest],
    url: str,
    key: str,
    model: str,
    provider: str = "openai",
    system_prompt: str = "",
    parallel: int = 10,
    timeout: float = 60.0,
    max_tokens: int = 512,
    on_progress: Optional[Callable[[EvalResult], None]] = None,
) -> list[EvalResult]:
    """Run the full evaluation."""
    semaphore = asyncio.Semaphore(parallel)
    async with httpx.AsyncClient(follow_redirects=True) as client:
        tasks = [
            asyncio.create_task(
                _run_single(
                    client, req, url, key, model, provider, system_prompt,
                    timeout, max_tokens, semaphore, on_progress,
                )
            )
            for req in requests
        ]
        results = []
        for coro in asyncio.as_completed(tasks):
            r = await coro
            results.append(r)
        return results


def save_results(results: list[EvalResult], path: str) -> None:
    """Save results to JSON."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in results], f, indent=2, ensure_ascii=False)
