"""
共用網路工具模組

集中處理 timeout、retry、exponential backoff、jitter 與重試日誌。
"""

from __future__ import annotations

import random
import socket
import time
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

import requests


DEFAULT_NETWORK_CONFIG: Dict[str, Any] = {
    'timeout_seconds': 10,
    'retry': {
        'enabled': True,
        'max_retries': 2,
        'backoff_strategy': 'exponential',
        'initial_delay_seconds': 0.5,
        'multiplier': 2.0,
        'max_delay_seconds': 5.0,
        'jitter_seconds': 0.25,
    }
}


@dataclass(frozen=True)
class RetryPolicy:
    """正規化後的 retry policy。"""

    timeout_seconds: float
    enabled: bool
    max_retries: int
    backoff_strategy: str
    initial_delay_seconds: float
    multiplier: float
    max_delay_seconds: float
    jitter_seconds: float


@dataclass(frozen=True)
class RetryExecutionResult:
    """單次重試流程的執行結果。"""

    value: Any
    attempts_used: int
    retries_used: int


class RetryExhaustedError(Exception):
    """重試耗盡後拋出的例外，保留最後一次錯誤與嘗試次數。"""

    def __init__(self, message: str, attempts_used: int, last_error: Exception):
        super().__init__(message)
        self.attempts_used = attempts_used
        self.retries_used = max(attempts_used - 1, 0)
        self.last_error = last_error


def merge_network_config(network_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """將外部設定與預設值深度合併。"""
    merged = deepcopy(DEFAULT_NETWORK_CONFIG)
    incoming = network_config or {}
    retry_incoming = incoming.get('retry', {}) if isinstance(incoming, dict) else {}

    if isinstance(incoming, dict):
        for key, value in incoming.items():
            if key != 'retry':
                merged[key] = value

    if isinstance(retry_incoming, dict):
        merged['retry'].update(retry_incoming)

    return merged


def validate_network_config(network_config: Optional[Dict[str, Any]]) -> None:
    """驗證 network 設定是否合法。"""
    config = merge_network_config(network_config)
    retry_config = config['retry']
    allowed_strategies = {'fixed', 'exponential'}

    if config['timeout_seconds'] <= 0:
        raise ValueError("network.timeout_seconds 必須大於 0")

    if retry_config['max_retries'] < 0:
        raise ValueError("network.retry.max_retries 不可為負數")

    if retry_config['backoff_strategy'] not in allowed_strategies:
        raise ValueError(
            "network.retry.backoff_strategy 必須是 fixed 或 exponential"
        )

    if retry_config['initial_delay_seconds'] < 0:
        raise ValueError("network.retry.initial_delay_seconds 不可為負數")

    if retry_config['multiplier'] < 1:
        raise ValueError("network.retry.multiplier 必須大於或等於 1")

    if retry_config['max_delay_seconds'] < 0:
        raise ValueError("network.retry.max_delay_seconds 不可為負數")

    if retry_config['jitter_seconds'] < 0:
        raise ValueError("network.retry.jitter_seconds 不可為負數")


def build_retry_policy(network_config: Optional[Dict[str, Any]] = None) -> RetryPolicy:
    """建立正規化後的 RetryPolicy。"""
    validate_network_config(network_config)
    config = merge_network_config(network_config)
    retry_config = config['retry']

    return RetryPolicy(
        timeout_seconds=float(config['timeout_seconds']),
        enabled=bool(retry_config['enabled']),
        max_retries=int(retry_config['max_retries']),
        backoff_strategy=str(retry_config['backoff_strategy']),
        initial_delay_seconds=float(retry_config['initial_delay_seconds']),
        multiplier=float(retry_config['multiplier']),
        max_delay_seconds=float(retry_config['max_delay_seconds']),
        jitter_seconds=float(retry_config['jitter_seconds']),
    )


def calculate_delay(policy: RetryPolicy, attempt_number: int) -> float:
    """計算下一次重試前等待時間。"""
    base_delay = policy.initial_delay_seconds

    if policy.backoff_strategy == 'exponential':
        base_delay *= policy.multiplier ** max(attempt_number - 1, 0)

    delay = min(base_delay, policy.max_delay_seconds)

    if policy.jitter_seconds > 0:
        delay += random.uniform(0, policy.jitter_seconds)

    return delay


def format_exception_message(exc: Exception) -> str:
    """產生適合記錄於 log 與結果細節的錯誤訊息。"""
    return f"{type(exc).__name__}: {exc}"


def is_retryable_requests_exception(exc: Exception) -> bool:
    """判斷 requests 相關例外是否可重試。"""
    if isinstance(exc, (requests.Timeout, requests.ConnectionError)):
        return True

    if isinstance(exc, requests.HTTPError):
        response = exc.response
        if response is None:
            return False
        return response.status_code == 429 or 500 <= response.status_code < 600

    return False


def is_retryable_socket_exception(exc: Exception) -> bool:
    """判斷 socket 相關例外是否可重試。"""
    return isinstance(
        exc,
        (
            socket.timeout,
            TimeoutError,
            ConnectionError,
            ConnectionRefusedError,
            ConnectionResetError,
            socket.gaierror,
            OSError,
        )
    )


def execute_with_retry(
    operation_name: str,
    target: str,
    func: Callable[[], Any],
    policy: RetryPolicy,
    logger,
    retryable: Optional[Callable[[Exception], bool]] = None,
) -> RetryExecutionResult:
    """執行共用 retry 流程，成功時回傳結果，失敗時拋出 RetryExhaustedError。"""
    total_attempts = policy.max_retries + 1 if policy.enabled else 1
    retryable_check = retryable or (lambda exc: is_retryable_requests_exception(exc))
    last_error: Optional[Exception] = None

    for attempt in range(1, total_attempts + 1):
        try:
            value = func()
            if attempt > 1:
                logger.info(
                    "%s 成功: target=%s, attempt=%s/%s, retries_used=%s",
                    operation_name,
                    target,
                    attempt,
                    total_attempts,
                    attempt - 1,
                )
            return RetryExecutionResult(
                value=value,
                attempts_used=attempt,
                retries_used=attempt - 1,
            )
        except Exception as exc:
            last_error = exc
            should_retry = attempt < total_attempts and retryable_check(exc)

            if not should_retry:
                logger.error(
                    "%s 失敗: target=%s, attempt=%s/%s, retries_used=%s, error=%s",
                    operation_name,
                    target,
                    attempt,
                    total_attempts,
                    attempt - 1,
                    format_exception_message(exc),
                )
                raise RetryExhaustedError(
                    f"{operation_name} 失敗: {format_exception_message(exc)}",
                    attempts_used=attempt,
                    last_error=exc,
                ) from exc

            delay_seconds = calculate_delay(policy, attempt)
            logger.warning(
                "%s 重試: target=%s, attempt=%s/%s, retry=%s/%s, next_delay=%.2fs, error=%s",
                operation_name,
                target,
                attempt,
                total_attempts,
                attempt,
                policy.max_retries,
                delay_seconds,
                format_exception_message(exc),
            )
            time.sleep(delay_seconds)

    raise RetryExhaustedError(
        f"{operation_name} 失敗: {format_exception_message(last_error or Exception('unknown error'))}",
        attempts_used=total_attempts,
        last_error=last_error or Exception('unknown error'),
    )