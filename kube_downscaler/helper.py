import datetime
import json
import logging
import os
import re
import sys
import time
from typing import Callable
from typing import Match
from typing import Optional
from typing import TypeVar

import pykube
import pytz
import requests

from kube_downscaler.tokenbucket import TokenBucket

logger = logging.getLogger(__name__)

DEFAULT_TIMEZONE = os.getenv("DEFAULT_TIMEZONE", None)
DEFAULT_WEEKFRAME = os.getenv("DEFAULT_WEEKFRAME", None)

WEEKDAYS = ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"]

TIME_SPEC_PATTERN = re.compile(
    r"^([a-zA-Z]{3})-([a-zA-Z]{3}) (\d\d):(\d\d)-(\d\d):(\d\d) (?P<tz>[a-zA-Z/_]+)$"
)
TIME_SPEC_PATTERN_WO_TZ = re.compile(r".*(\d\d)$")
TIME_SPEC_PATTERN_WO_WF = re.compile(
    r"^(\d\d):(\d\d)-(\d\d):(\d\d) (?P<tz>[a-zA-Z/_]+)$"
)
_ISO_8601_TIME_SPEC_PATTERN = r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[-+]\d{2}:\d{2})"
ABSOLUTE_TIME_SPEC_PATTERN = re.compile(
    r"^{0}-{0}$".format(_ISO_8601_TIME_SPEC_PATTERN)
)
TOKEN_BUCKET: TokenBucket
MAX_RETRIES: int


def matches_time_spec(time: datetime.datetime, spec: str):
    if spec.lower() == "always":
        return True
    elif spec.lower() == "never":
        return False
    for spec_ in spec.split(","):
        spec_ = spec_.strip()
        match = TIME_SPEC_PATTERN_WO_TZ.match(spec_)
        if match and not ABSOLUTE_TIME_SPEC_PATTERN.match(spec_):
            if DEFAULT_TIMEZONE:
                spec_ = spec_ + " " + DEFAULT_TIMEZONE
            else:
                raise ValueError(
                    "No default timezone defined in environment variable 'DEFAULT_TIMEZONE'"
                )
        if TIME_SPEC_PATTERN_WO_WF.match(spec_):
            if DEFAULT_WEEKFRAME:
                spec_ = DEFAULT_WEEKFRAME + " " + spec_
            else:
                raise ValueError(
                    "No default week frame defined in environment variable 'DEFAULT_WEEKFRAME'"
                )
        recurring_match = TIME_SPEC_PATTERN.match(spec_)
        if recurring_match is not None and _matches_recurring_time_spec(
            time, recurring_match
        ):
            return True
        absolute_match = ABSOLUTE_TIME_SPEC_PATTERN.match(spec_)
        if absolute_match and _matches_absolute_time_spec(time, absolute_match):
            return True
        if not recurring_match and not absolute_match:
            raise ValueError(
                f'Time spec value "{spec_}" does not match format ("Mon-Fri 06:30-20:30 Europe/Berlin" or "2019-01-01T00:00:00+00:00-2019-01-02T12:34:56+00:00")'
            )
    return False


def _matches_recurring_time_spec(time: datetime.datetime, match: Match):
    tz = pytz.timezone(match.group("tz"))
    local_time = tz.fromutc(time.replace(tzinfo=tz))
    day_from = WEEKDAYS.index(match.group(1).upper())
    day_to = WEEKDAYS.index(match.group(2).upper())
    if day_from > day_to:
        # wrap around, e.g. Sun-Fri (makes sense for countries with work week starting on Sunday)
        day_matches = local_time.weekday() >= day_from or local_time.weekday() <= day_to
    else:
        # e.g. Mon-Fri
        day_matches = day_from <= local_time.weekday() <= day_to
    local_time_minutes = local_time.hour * 60 + local_time.minute
    minute_from = int(match.group(3)) * 60 + int(match.group(4))
    minute_to = int(match.group(5)) * 60 + int(match.group(6))
    time_matches = minute_from <= local_time_minutes < minute_to
    return day_matches and time_matches


def _matches_absolute_time_spec(time: datetime.datetime, match: Match):
    time_from = datetime.datetime.fromisoformat(match.group(1))
    time_to = datetime.datetime.fromisoformat(match.group(2))
    return time_from <= time <= time_to


def get_kube_api(timeout: int):
    config = pykube.KubeConfig.from_env()
    api = pykube.HTTPClient(config, timeout=timeout)
    return api


def parse_int_or_percent(value, context, allow_negative):
    s = str(value).strip()

    if s.endswith("%"):
        number_part = s[:-1].strip()
        if number_part.isdigit():
            val = int(number_part)
            if 0 <= val <= 100:
                return val, True
            else:
                raise ValueError(f"Percentage in {context} must be between 0 and 100.")
        else:
            raise ValueError(
                f"Invalid percentage format in {context}: must be digits before '%'."
            )

    if allow_negative:
        if (s.startswith("-") and s[1:].isdigit()) or s.isdigit():
            return int(s), False
    else:
        if s.isdigit():
            return int(s), False

    raise ValueError(
        f"Invalid format for {context}: must be an integer like '10' or a percentage like '10%'."
    )


def add_event(resource, message: str, reason: str, event_type: str, dry_run: bool):
    uid = resource.metadata.get("uid")
    try:
        event = call_with_exponential_backoff(
            lambda: pykube.objects.Event.objects(resource.api)
            .filter(
                namespace=resource.namespace,
                field_selector={
                    "involvedObject.uid": resource.metadata.get("uid"),
                    "reason": reason,
                    "type": event_type,
                },
            )
            .get_or_none(),
            context_msg=f"getting event for id {uid}",
        )
    except requests.HTTPError as e:
        event = None
        logger.error(f"Could not get event for id {uid}: {e}")
        if e.response.status_code == 429:
            logger.warning(
                f"KubeDownscaler is being rate-limited by the Kubernetes API while getting Events in namespace {resource.namespace} (429 Too Many Requests)."
            )
    if event and event.obj["message"] == message:
        now = datetime.datetime.now(datetime.timezone.utc)
        timestamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        event.obj["count"] = event.obj["count"] + 1
        event.obj["lastTimestamp"] = timestamp
        try:
            call_with_exponential_backoff(
                lambda: event.update(),
                context_msg=f"updating event for id {uid}",
            )
            return event
        except requests.HTTPError as e:
            logger.error(f"Could not update event {event.obj}: {e}")
            if e.response.status_code == 429:
                logger.warning(
                    f"KubeDownscaler is being rate-limited by the Kubernetes API while updating Event with id {uid} in namespace {resource.namespace} (429 Too Many Requests)."
                )
            else:
                raise e

    return create_event(resource, message, reason, event_type, dry_run)


def create_event(resource, message: str, reason: str, event_type: str, dry_run: bool):
    now = datetime.datetime.now(datetime.timezone.utc)
    timestamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    event = pykube.Event(
        resource.api,
        {
            "metadata": {
                "namespace": resource.namespace,
                "generateName": "py-kube-downscaler-",
            },
            "type": event_type,
            "count": 1,
            "firstTimestamp": timestamp,
            "lastTimestamp": timestamp,
            "reason": reason,
            "involvedObject": {
                "apiVersion": resource.version,
                "name": resource.name,
                "namespace": resource.namespace,
                "kind": resource.kind,
                "resourceVersion": resource.metadata.get("resourceVersion"),
                # https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#uids
                "uid": resource.metadata.get("uid"),
            },
            "message": message,
            "source": {"component": "py-kube-downscaler"},
        },
    )
    if not dry_run:
        try:
            call_with_exponential_backoff(
                lambda: event.create(),
                context_msg=f"creating event for {resource.namespace}/{resource.name}",
            )
            return event
        except requests.HTTPError as e:
            logger.error(f"Could not create event {event.obj}: {e}")
            if e.response.status_code == 429:
                logger.warning(
                    f"KubeDownscaler is being rate-limited by the Kubernetes API while creating {reason} event for {resource.namespace}/{resource.name} (429 Too Many Requests)."
                )
            else:
                raise e


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "time": self.formatTime(record),
                "severity": record.levelname,
                "message": record.getMessage().replace('"', "'"),
            }
        )


def setup_logging(debug: bool, json_logs: bool):
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(logging.DEBUG if debug else logging.INFO)

    stderr_handler = logging.StreamHandler(sys.stderr)

    formatter: logging.Formatter
    if json_logs:
        formatter = JsonFormatter()
    else:
        formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")

    stderr_handler.setFormatter(formatter)
    root_logger.addHandler(stderr_handler)


def initialize_token_bucket(qps, burst):
    global TOKEN_BUCKET
    if qps == 0 and burst == 0:
        TOKEN_BUCKET = None
    TOKEN_BUCKET = TokenBucket(qps=qps, burst=burst)


def initialize_max_retries(max_retries):
    global MAX_RETRIES
    MAX_RETRIES = max_retries


T = TypeVar("T")


def call_with_exponential_backoff(
    func: Callable[..., T],
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    backoff_factor: int = 2,
    jitter: bool = True,
    retry_on_status_codes: tuple = (429,),
    context_msg: Optional[str] = None,
    use_token_bucket: bool = True,
) -> T:
    """
    Generic function to call any function with exponential backoff on HTTP errors.

    Args:
        func: The function to call
        base_delay: Initial delay in seconds
        max_delay: Maximum delay in seconds (caps the exponential growth)
        backoff_factor: Multiplier for exponential backoff (default: 2 for doubling)
        jitter: Whether to add random jitter to prevent thundering herd
        retry_on_status_codes: Tuple of HTTP status codes that should trigger retry
        context_msg: Optional context message for logging
        use_token_bucket: Whether to use the global token bucket (default: True)

    Returns:
        The return value of the called function

    Raises:
        The last exception if max retries exceeded or non-retryable error occurs
    """
    global TOKEN_BUCKET
    retry_count = 0
    last_exception = None

    if MAX_RETRIES and MAX_RETRIES > 0:
        while retry_count <= MAX_RETRIES:
            try:
                if use_token_bucket and TOKEN_BUCKET:
                    TOKEN_BUCKET.acquire()

                return func()

            except requests.HTTPError as e:
                last_exception = e
                if e.response.status_code in retry_on_status_codes:
                    if retry_count >= MAX_RETRIES:
                        error_msg = f"Max retries ({MAX_RETRIES}) reached"
                        if context_msg:
                            error_msg += f" for {context_msg}"
                        error_msg += ". giving up."
                        logger.error(error_msg)
                        raise e

                    # check for "Retry-After" header
                    retry_after = e.response.headers.get("Retry-After")

                    if retry_after:
                        try:
                            # retry-After can be in seconds (integer) or HTTP date format
                            if retry_after.isdigit():
                                delay = float(retry_after)
                            else:
                                # try parsing as HTTP date
                                from email.utils import parsedate_to_datetime

                                retry_date = parsedate_to_datetime(retry_after)
                                delay = (
                                    retry_date
                                    - datetime.datetime.now(retry_date.tzinfo)
                                ).total_seconds()

                            # cap the delay at max_delay
                            delay = min(delay, max_delay)

                            logger.info(
                                f"using Retry-After header value: {delay:.2f} seconds"
                            )
                        except (ValueError, TypeError) as parse_error:
                            logger.warning(
                                f"failed to parse Retry-After header '{retry_after}': {parse_error}. Using exponential backoff."
                            )
                            # fall back to exponential backoff
                            delay = min(
                                base_delay * (backoff_factor**retry_count), max_delay
                            )
                    else:
                        # calculate exponential backoff
                        delay = min(
                            base_delay * (backoff_factor**retry_count), max_delay
                        )

                    # add jitter if not using "Retry-After" header
                    if jitter and not retry_after:
                        jitter_amount = delay * 0.1 * (time.time() % 1)
                        delay += jitter_amount

                    warning_msg = f"HTTP {e.response.status_code} error"
                    if context_msg:
                        warning_msg += f" for {context_msg}"
                    warning_msg += f". retrying in {delay:.2f} seconds (attempt {retry_count + 1}/{MAX_RETRIES})"
                    logger.warning(warning_msg)

                    time.sleep(delay)
                    retry_count += 1
                else:
                    # re-raise non-retryable errors immediately
                    raise e

        if last_exception:
            raise last_exception
        raise RuntimeError("Unexpected state: no exception but no successful return")

    else:
        if use_token_bucket and TOKEN_BUCKET:
            TOKEN_BUCKET.acquire()

        return func()
