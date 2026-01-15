from unittest.mock import patch

import requests
from requests.models import Response

from kube_downscaler.helper import call_with_exponential_backoff
from kube_downscaler.tokenbucket import TokenBucket


def make_http_error(status_code: int) -> requests.HTTPError:
    response = Response()
    response.status_code = status_code
    return requests.HTTPError(response=response)


def test_call_with_exponential_backoff_retries_then_succeeds(monkeypatch):
    monkeypatch.setattr("kube_downscaler.helper.MAX_RETRIES", 3, raising=False)
    monkeypatch.setattr("kube_downscaler.helper.TOKEN_BUCKET", None, raising=False)
    call_count = {"count": 0}

    def flaky_function():
        call_count["count"] += 1
        if call_count["count"] < 3:
            raise make_http_error(429)
        return "success"

    # patch time.sleep so tests run instantly
    with patch("time.sleep") as mock_sleep:
        result = call_with_exponential_backoff(
            func=flaky_function,
            base_delay=1.0,
            max_delay=10.0,
            backoff_factor=3,
            jitter=False,
            retry_on_status_codes=(429,),
            use_token_bucket=False,
        )

    assert result == "success"
    assert call_count["count"] == 3

    # verify backoff delays: 1s, then 3s (delay = min(base_delay * (backoff_factor ** retry_count), max_delay))
    mock_sleep.assert_any_call(1.0)
    mock_sleep.assert_any_call(3.0)


def test_initial_tokens():
    tb = TokenBucket(qps=5, burst=10)
    assert tb.tokens == 10  # token bucket starts full


def test_acquire_with_enough_tokens():
    tb = TokenBucket(qps=5, burst=10)
    tb.acquire(3)
    assert tb.tokens == 7  # 10 - 3 tokens used


def test_acquire_blocks_when_not_enough_tokens():
    tb = TokenBucket(qps=5, burst=10)
    tb.tokens = 2  # only 2 tokens available at the moment

    # we acquire 5 tokens → should block until 3 more refill
    with patch("time.sleep") as mock_sleep:
        tb.acquire(5)
        # the token bucket will calculate sleep = (5-2)/5 = 0.6s
        mock_sleep.assert_called()  # ensures sleep was called


def test_token_refill_over_time():
    tb = TokenBucket(qps=2, burst=5)
    tb.tokens = 2
    tb.last_update -= 1.5  # simulate 1.5 seconds elapsed

    # acquire 3 tokens → 2 + 1.5*2 = 5 tokens available (capped at burst)
    with patch("time.sleep") as mock_sleep:
        tb.acquire(5)
        assert tb.tokens == 0
        mock_sleep.assert_not_called()  # enough tokens, no sleep needed


def test_burst_limit():
    tb = TokenBucket(qps=5, burst=10)
    tb.tokens = 10
    tb.last_update -= 10  # simulate time passes

    # tokens should not exceed burst
    tb.acquire(1)
    assert tb.tokens <= tb.burst
