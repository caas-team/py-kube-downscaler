import datetime
import logging
import re
import os
from typing import Match

import pykube
import pytz

logger = logging.getLogger(__name__)

DEFAULT_PERIOD_MINUTES = 30

WEEKDAYS = ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"]

TIME_SPEC_PATTERN = re.compile(
    r"^([a-zA-Z]{3})-([a-zA-Z]{3}) (\d\d):(\d\d)-(\d\d):(\d\d) (?P<tz>[a-zA-Z/_]+)$"
)
TIME_SPEC_PATTERN_WO_TZ = re.compile(r'.*(\d\d)$')
TIME_SPEC_PATTERN_JJHHMMTZ = re.compile(r'^([a-zA-Z]{3})-([a-zA-Z]{3}) (\d\d):(\d\d) (?P<tz>[a-zA-Z/_]+)$')
TIME_SPEC_PATTERN_HHMMTZ = re.compile(r'^(\d\d):(\d\d) (?P<tz>[a-zA-Z/_]+)$')
_ISO_8601_TIME_SPEC_PATTERN = r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[-+]\d{2}:\d{2})"
ABSOLUTE_TIME_SPEC_PATTERN = re.compile(
    r"^{0}-{0}$".format(_ISO_8601_TIME_SPEC_PATTERN)
)


def matches_time_spec(time: datetime.datetime, spec: str):
    if spec.lower() == "always":
        return True
    elif spec.lower() == "never":
        return False
    for spec_ in spec.split(","):
        spec_ = spec_.strip()
        match = TIME_SPEC_PATTERN_WO_TZ.match(spec_)
        if match and not ABSOLUTE_TIME_SPEC_PATTERN.match(spec_):
          spec_ = spec_ + ' ' + os.environ['TZ']
        if TIME_SPEC_PATTERN_HHMMTZ.match(spec_):
          spec_ = 'Mon-Sun ' + spec_ 
        match = TIME_SPEC_PATTERN_JJHHMMTZ.match(spec_)
        if match:
          end_of_period = datetime.datetime(2000,1,1,int(match.group(3)),int(match.group(4)),0) + datetime.timedelta(minutes=DEFAULT_PERIOD_MINUTES)
          if (int(match.group(3)) * 60 + int(match.group(4))) >= (60 * 24 - DEFAULT_PERIOD_MINUTES):
             end_of_period = datetime.datetime(2000,1,1,23,59,0)
          spec_ = match.group(1) + '-' + match.group(2) + ' ' + match.group(3) + ':' + match.group(4)
          spec_ = spec_ + '-' + end_of_period.strftime("%H:%M") + ' ' + match.group('tz')
        logger.debug('=> spec_ evaluated = "%s"', spec_)
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
    event = (
        pykube.objects.Event.objects(resource.api)
        .filter(
            namespace=resource.namespace,
            field_selector={
                "involvedObject.uid": resource.metadata.get("uid"),
                "reason": reason,
                "type": event_type,
            },
        )
        .get_or_none()
    )
    if event and event.obj["message"] == message:
        now = datetime.datetime.now(datetime.timezone.utc)
        timestamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        event.obj["count"] = event.obj["count"] + 1
        event.obj["lastTimestamp"] = timestamp
        try:
            event.update()
            return event
        except Exception as e:
            logger.error(f"Could not update event {event.obj}: {e}")
        return

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
            event.create()
            return event
        except Exception as e:
            logger.error(f"Could not create event {event.obj}: {e}")
