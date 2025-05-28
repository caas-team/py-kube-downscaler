import json
import logging
import re
from datetime import datetime
from datetime import timezone
from unittest.mock import MagicMock

import pykube
import pytest
from pykube import DaemonSet
from pykube import Deployment
from pykube import HorizontalPodAutoscaler
from pykube import PodDisruptionBudget
from pykube.exceptions import HTTPError

from kube_downscaler.resources.keda import ScaledObject
from kube_downscaler.resources.stack import Stack
from kube_downscaler.scaler import autoscale_resource
from kube_downscaler.scaler import DOWNSCALE_PERIOD_ANNOTATION
from kube_downscaler.scaler import DOWNTIME_REPLICAS_ANNOTATION
from kube_downscaler.scaler import EXCLUDE_ANNOTATION
from kube_downscaler.scaler import EXCLUDE_UNTIL_ANNOTATION
from kube_downscaler.scaler import ORIGINAL_REPLICAS_ANNOTATION
from kube_downscaler.scaler import UPSCALE_PERIOD_ANNOTATION


@pytest.fixture
def resource():
    res = MagicMock()
    res.kind = "MockResource"
    res.namespace = "mock"
    res.name = "res-1"
    res.annotations = {}
    return res


def test_swallow_exception(monkeypatch, resource, caplog):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    caplog.set_level(logging.ERROR)
    resource.annotations = {}
    resource.replicas = 1
    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    resource.metadata = {"creationTimestamp": "invalid-timestamp!"}
    autoscale_resource(
        resource,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=True,
        max_retries_on_conflict=0,
        api=api,
        kind=Deployment,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )
    assert resource.replicas == 1
    resource.update.assert_not_called()
    # check that the failure was logged
    msg = "Failed to process MockResource mock/res-1: time data 'invalid-timestamp!' does not match any format (%Y-%m-%dT%H:%M:%SZ, %Y-%m-%dT%H:%M, %Y-%m-%d %H:%M, %Y-%m-%d)"
    assert caplog.record_tuples == [("kube_downscaler.scaler", logging.ERROR, msg)]


def test_swallow_exception_with_event(monkeypatch, resource, caplog):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.add_event", MagicMock(return_value=None)
    )
    caplog.set_level(logging.ERROR)
    resource.annotations = {}
    resource.replicas = 1
    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    resource.metadata = {"creationTimestamp": "invalid-timestamp!"}
    autoscale_resource(
        resource,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=True,
        max_retries_on_conflict=0,
        api=api,
        kind=Deployment,
        now=now,
        enable_events=True,
        matching_labels=frozenset([re.compile("")]),
    )
    assert resource.replicas == 1
    resource.update.assert_not_called()
    # check that the failure was logged
    msg = "Failed to process MockResource mock/res-1: time data 'invalid-timestamp!' does not match any format (%Y-%m-%dT%H:%M:%SZ, %Y-%m-%dT%H:%M, %Y-%m-%d %H:%M, %Y-%m-%d)"
    assert caplog.record_tuples == [("kube_downscaler.scaler", logging.ERROR, msg)]


def test_exclude(resource, monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    resource.annotations = {EXCLUDE_ANNOTATION: "true"}
    resource.replicas = 1
    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    resource.metadata = {"creationTimestamp": "2018-10-23T21:55:00Z"}
    autoscale_resource(
        resource,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=True,
        max_retries_on_conflict=0,
        api=api,
        kind=Deployment,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )
    assert resource.replicas == 1
    resource.update.assert_not_called()
    assert ORIGINAL_REPLICAS_ANNOTATION not in resource.annotations


def test_exclude_until_invalid_time(resource, caplog, monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    caplog.set_level(logging.WARNING)
    resource.annotations = {EXCLUDE_UNTIL_ANNOTATION: "some-invalid-timestamp"}
    resource.replicas = 1
    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    resource.metadata = {"creationTimestamp": "2018-10-23T21:55:00Z"}
    autoscale_resource(
        resource,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="never",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=True,
        max_retries_on_conflict=0,
        api=api,
        kind=Deployment,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )
    assert resource.replicas == 0
    assert resource.annotations[ORIGINAL_REPLICAS_ANNOTATION] == "1"
    # dry run will update the object properties, but won't call the Kubernetes API (update)
    resource.update.assert_not_called()

    # check that the warning was logged
    msg = "Invalid annotation value for 'downscaler/exclude-until' on mock/res-1: time data 'some-invalid-timestamp' does not match any format (%Y-%m-%dT%H:%M:%SZ, %Y-%m-%dT%H:%M, %Y-%m-%d %H:%M, %Y-%m-%d)"
    assert caplog.record_tuples == [("kube_downscaler.scaler", logging.WARNING, msg)]


def test_dry_run(resource, monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    resource.annotations = {}
    resource.replicas = 1
    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    resource.metadata = {"creationTimestamp": "2018-10-23T21:55:00Z"}
    autoscale_resource(
        resource,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=True,
        max_retries_on_conflict=0,
        api=api,
        kind=Deployment,
        now=now,
        grace_period=0,
        downtime_replicas=0,
        matching_labels=frozenset([re.compile("")]),
    )
    assert resource.replicas == 0
    assert resource.annotations[ORIGINAL_REPLICAS_ANNOTATION] == "1"
    # dry run will update the object properties, but won't call the Kubernetes API (update)
    resource.update.assert_not_called()


def test_grace_period(resource, monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    resource.annotations = {}
    resource.replicas = 1
    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    resource.metadata = {"creationTimestamp": "2018-10-23T21:55:00Z"}
    # resource was only created 1 minute ago, grace period is 5 minutes
    autoscale_resource(
        resource,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=False,
        max_retries_on_conflict=0,
        api=api,
        kind=Deployment,
        now=now,
        grace_period=300,
        matching_labels=frozenset([re.compile("")]),
    )
    assert resource.replicas == 1
    assert resource.annotations == {}
    resource.update.assert_not_called()


def test_downtime_always(resource, monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    resource.annotations = {EXCLUDE_ANNOTATION: "false"}
    resource.replicas = 1
    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    resource.metadata = {"creationTimestamp": "2018-10-23T21:55:00Z"}
    autoscale_resource(
        resource,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=False,
        max_retries_on_conflict=0,
        api=api,
        kind=Deployment,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )
    assert resource.replicas == 0
    resource.update.assert_called_once()
    assert resource.annotations[ORIGINAL_REPLICAS_ANNOTATION] == "1"


def test_downtime_interval(resource, monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    resource.annotations = {EXCLUDE_ANNOTATION: "false"}
    resource.replicas = 1
    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    resource.metadata = {"creationTimestamp": "2018-10-23T21:55:00Z"}
    autoscale_resource(
        resource,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="Mon-Fri 07:30-20:30 Europe/Berlin",
        default_downtime="always",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=False,
        max_retries_on_conflict=0,
        api=api,
        kind=Deployment,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )
    assert resource.replicas == 0
    resource.update.assert_called_once()
    assert resource.annotations[ORIGINAL_REPLICAS_ANNOTATION] == "1"


def test_forced_uptime(resource, monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    resource.annotations = {EXCLUDE_ANNOTATION: "false"}
    resource.replicas = 1
    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    resource.metadata = {"creationTimestamp": "2018-10-23T21:55:00Z"}
    autoscale_resource(
        resource,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="Mon-Fri 07:30-20:30 Europe/Berlin",
        default_downtime="always",
        forced_uptime=True,
        forced_downtime=False,
        dry_run=False,
        max_retries_on_conflict=0,
        api=api,
        kind=Deployment,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )
    assert resource.replicas == 1
    resource.update.assert_not_called()


def test_forced_downtime(resource, monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    resource.annotations = {EXCLUDE_ANNOTATION: "false"}
    resource.replicas = 1
    now = datetime.strptime("2018-10-23T15:00:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    resource.metadata = {"creationTimestamp": "2018-10-23T14:59:00Z"}
    autoscale_resource(
        resource,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="Mon-Fri 07:30-20:30 Europe/Berlin",
        default_downtime="always",
        forced_uptime=False,
        forced_downtime=True,
        dry_run=False,
        max_retries_on_conflict=0,
        api=api,
        kind=Deployment,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )
    assert resource.replicas == 0
    resource.update.assert_called_once()


def test_autoscale_bad_resource(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    try:
        autoscale_resource(
            upscale_target_only=False,
            resource=None,
            upscale_period="never",
            downscale_period="never",
            default_uptime="never",
            default_downtime="always",
            forced_uptime=False,
            forced_downtime=False,
            dry_run=False,
            max_retries_on_conflict=0,
            api=api,
            kind=Deployment,
            now=now,
            matching_labels=frozenset([re.compile("")]),
        )
        raise AssertionError("Failed to error out with a bad resource")
    except Exception:
        pass


def test_scale_up(resource, monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    resource.annotations = {
        EXCLUDE_ANNOTATION: "false",
        ORIGINAL_REPLICAS_ANNOTATION: "3",
    }
    resource.replicas = 0
    now = datetime.strptime("2018-10-23T15:00:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    resource.metadata = {"creationTimestamp": "2018-10-23T21:55:00Z"}
    autoscale_resource(
        resource,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="Mon-Fri 07:30-20:30 Europe/Berlin",
        default_downtime="never",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=False,
        max_retries_on_conflict=0,
        api=api,
        kind=Deployment,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )
    assert resource.replicas == 3
    resource.update.assert_called_once()


def test_scale_up_downtime_replicas_annotation(resource, monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    """Cli argument downtime-replicas is 1, but for 1 specific deployment we want 0."""
    resource.annotations = {
        DOWNTIME_REPLICAS_ANNOTATION: "0",
        ORIGINAL_REPLICAS_ANNOTATION: "1",
    }
    resource.replicas = 0
    now = datetime.strptime("2018-10-23T15:00:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    resource.metadata = {"creationTimestamp": "2018-10-23T21:55:00Z"}
    autoscale_resource(
        resource,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="Mon-Fri 07:30-20:30 Europe/Berlin",
        default_downtime="never",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=False,
        max_retries_on_conflict=0,
        api=api,
        kind=Deployment,
        now=now,
        downtime_replicas=1,
        matching_labels=frozenset([re.compile("")]),
    )
    assert resource.replicas == 1
    resource.update.assert_called_once()


def test_downtime_replicas_annotation_invalid(resource, monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    resource.annotations = {DOWNTIME_REPLICAS_ANNOTATION: "x"}
    resource.replicas = 2
    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    resource.metadata = {"creationTimestamp": "2018-10-23T21:55:00Z"}
    autoscale_resource(
        resource,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=False,
        max_retries_on_conflict=0,
        api=api,
        kind=Deployment,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )
    assert resource.replicas == 2
    resource.update.assert_not_called()


def test_downtime_replicas_annotation_valid(resource, monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    resource.annotations = {DOWNTIME_REPLICAS_ANNOTATION: "1"}
    resource.replicas = 2
    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    resource.metadata = {"creationTimestamp": "2018-10-23T21:55:00Z"}
    autoscale_resource(
        resource,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=False,
        max_retries_on_conflict=0,
        api=api,
        kind=Deployment,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )
    assert resource.replicas == 1
    resource.update.assert_called_once()
    assert resource.annotations[ORIGINAL_REPLICAS_ANNOTATION] == "2"


def test_downtime_replicas_invalid(resource, monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    resource.replicas = 2
    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    resource.metadata = {"creationTimestamp": "2018-10-23T21:55:00Z"}
    autoscale_resource(
        resource,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=False,
        max_retries_on_conflict=0,
        api=api,
        kind=Deployment,
        now=now,
        downtime_replicas="x",
        matching_labels=frozenset([re.compile("")]),
    )
    assert resource.replicas == 2
    resource.update.assert_not_called()


def test_downtime_replicas_valid(resource, monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    resource.replicas = 2
    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    resource.metadata = {"creationTimestamp": "2018-10-23T21:55:00Z"}
    autoscale_resource(
        resource,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=False,
        max_retries_on_conflict=0,
        api=api,
        kind=Deployment,
        now=now,
        downtime_replicas=1,
        matching_labels=frozenset([re.compile("")]),
    )
    assert resource.replicas == 1
    resource.update.assert_called_once()


def test_set_annotation():
    api = MagicMock()
    api.config.namespace = "myns"
    resource = pykube.StatefulSet(
        api,
        {
            "metadata": {"name": "foo", "creationTimestamp": "2019-03-15T21:55:00Z"},
            "spec": {},
        },
    )
    resource.replicas = 1
    now = datetime.strptime("2019-03-15T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    autoscale_resource(
        resource,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=False,
        max_retries_on_conflict=0,
        api=api,
        kind=Deployment,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )
    api.patch.assert_called_once()
    patch_data = json.loads(api.patch.call_args[1]["data"])
    # ensure the original replicas annotation is send to the server
    assert patch_data == {
        "metadata": {
            "name": "foo",
            "creationTimestamp": "2019-03-15T21:55:00Z",
            "annotations": {ORIGINAL_REPLICAS_ANNOTATION: "1"},
        },
        "spec": {"replicas": 0},
    }


def test_downscale_always(resource, monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    resource.annotations = {EXCLUDE_ANNOTATION: "false"}
    resource.replicas = 1
    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    resource.metadata = {"creationTimestamp": "2018-10-23T21:55:00Z"}
    autoscale_resource(
        resource,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="always",
        default_uptime="always",
        default_downtime="never",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=False,
        max_retries_on_conflict=0,
        api=api,
        kind=Deployment,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )
    assert resource.replicas == 0
    resource.update.assert_called_once()
    assert resource.annotations[ORIGINAL_REPLICAS_ANNOTATION] == "1"


def test_downscale_period(resource, monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    resource.annotations = {EXCLUDE_ANNOTATION: "false"}
    resource.replicas = 1
    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    resource.metadata = {"creationTimestamp": "2018-10-23T21:55:00Z"}
    autoscale_resource(
        resource,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="Mon-Fri 20:30-24:00 Europe/Berlin",
        default_uptime="always",
        default_downtime="never",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=False,
        max_retries_on_conflict=0,
        api=api,
        kind=Deployment,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )
    assert resource.replicas == 0
    resource.update.assert_called_once()
    assert resource.annotations[ORIGINAL_REPLICAS_ANNOTATION] == "1"


def test_downscale_period_overlaps(resource, monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    resource.annotations = {DOWNTIME_REPLICAS_ANNOTATION: "1"}
    resource.replicas = 2
    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    resource.metadata = {"creationTimestamp": "2018-10-23T21:55:00Z"}
    autoscale_resource(
        resource,
        upscale_target_only=False,
        upscale_period="Mon-Fri 20:30-24:00 Europe/Berlin",
        downscale_period="Mon-Fri 20:30-24:00 Europe/Berlin",
        default_uptime="always",
        default_downtime="never",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=False,
        max_retries_on_conflict=0,
        api=api,
        kind=Deployment,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )
    assert resource.replicas == 2
    resource.update.assert_not_called()


def test_downscale_period_not_match(resource, monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    resource.annotations = {DOWNTIME_REPLICAS_ANNOTATION: "1"}
    resource.replicas = 2
    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    resource.metadata = {"creationTimestamp": "2018-10-23T21:55:00Z"}
    autoscale_resource(
        resource,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="Mon-Fri 07:30-10:00 Europe/Berlin",
        default_uptime="always",
        default_downtime="never",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=False,
        max_retries_on_conflict=0,
        api=api,
        kind=Deployment,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )
    assert resource.replicas == 2
    resource.update.assert_not_called()


def test_downscale_period_resource_overrides_never(resource, monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    resource.annotations = {
        DOWNSCALE_PERIOD_ANNOTATION: "Mon-Fri 20:30-24:00 Europe/Berlin"
    }
    resource.replicas = 1
    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    resource.metadata = {"creationTimestamp": "2018-10-23T21:55:00Z"}
    autoscale_resource(
        resource,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="always",
        default_downtime="never",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=False,
        max_retries_on_conflict=0,
        api=api,
        kind=Deployment,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )
    assert resource.replicas == 0
    resource.update.assert_called_once()


def test_downscale_period_resource_overrides_namespace(resource, monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    resource.annotations = {
        DOWNSCALE_PERIOD_ANNOTATION: "Mon-Fri 20:30-24:00 Europe/Berlin"
    }
    resource.replicas = 1
    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    resource.metadata = {"creationTimestamp": "2018-10-23T21:55:00Z"}
    autoscale_resource(
        resource,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="always",
        default_downtime="never",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=False,
        max_retries_on_conflict=0,
        api=api,
        kind=Deployment,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )
    assert resource.replicas == 0
    resource.update.assert_called_once()


def test_upscale_period_resource_overrides_never(resource, monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    resource.annotations = {
        UPSCALE_PERIOD_ANNOTATION: "Mon-Fri 20:30-24:00 Europe/Berlin",
        ORIGINAL_REPLICAS_ANNOTATION: 1,
    }
    resource.replicas = 0
    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    resource.metadata = {"creationTimestamp": "2018-10-23T21:55:00Z"}
    autoscale_resource(
        resource,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="always",
        default_downtime="never",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=False,
        max_retries_on_conflict=0,
        api=api,
        kind=Deployment,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )
    assert resource.replicas == 1
    resource.upd


def test_upscale_period_resource_overrides_namespace(resource, monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    resource.annotations = {
        UPSCALE_PERIOD_ANNOTATION: "Mon-Fri 20:30-24:00 Europe/Berlin",
        ORIGINAL_REPLICAS_ANNOTATION: 1,
    }
    resource.replicas = 0
    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    resource.metadata = {"creationTimestamp": "2018-10-23T21:55:00Z"}
    autoscale_resource(
        resource,
        upscale_target_only=False,
        upscale_period="Mon-Fri 22:00-24:00 Europe/Berlin",
        downscale_period="never",
        default_uptime="always",
        default_downtime="never",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=False,
        max_retries_on_conflict=0,
        api=api,
        kind=Deployment,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )
    assert resource.replicas == 1
    resource.upd


def test_downscale_stack_deployment_ignored(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    resource = MagicMock()
    resource.kind = Deployment.kind
    resource.version = Deployment.version
    resource.namespace = "mock"
    resource.name = "res-1"
    resource.metadata = {
        "creationTimestamp": "2018-10-23T21:55:00Z",
        "ownerReferences": [{"apiVersion": Stack.version, "kind": Stack.kind}],
    }
    resource.replicas = 1
    resource.annotations = {}

    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    autoscale_resource(
        resource,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=False,
        max_retries_on_conflict=0,
        api=api,
        kind=Deployment,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )
    assert resource.replicas == 1
    resource.update.assert_not_called()
    assert ORIGINAL_REPLICAS_ANNOTATION not in resource.annotations


def test_downscale_replicas_not_zero(resource, monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    resource.annotations = {EXCLUDE_ANNOTATION: "false"}
    resource.replicas = 3
    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    resource.metadata = {"creationTimestamp": "2018-10-23T21:55:00Z"}
    autoscale_resource(
        resource,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=False,
        max_retries_on_conflict=0,
        api=api,
        kind=Deployment,
        now=now,
        downtime_replicas=1,
        matching_labels=frozenset([re.compile("")]),
    )
    assert resource.replicas == 1
    assert resource.annotations[ORIGINAL_REPLICAS_ANNOTATION] == "3"
    autoscale_resource(
        resource,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=False,
        max_retries_on_conflict=0,
        api=api,
        kind=Deployment,
        now=now,
        downtime_replicas=1,
        matching_labels=frozenset([re.compile("")]),
    )
    assert resource.replicas == 1
    assert resource.annotations[ORIGINAL_REPLICAS_ANNOTATION] == "3"
    resource.update.assert_called_once()


def test_downscale_stack_with_autoscaling(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    stack = Stack(
        None,
        {
            "metadata": {
                "name": "my-stack",
                "namespace": "my-ns",
                "creationTimestamp": "2018-10-23T21:55:00Z",
            },
            "spec": {"horizontalPodAutoscaler": {"maxReplicas": 4}},
        },
    )

    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    assert stack.replicas == 4
    autoscale_resource(
        stack,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=True,
        max_retries_on_conflict=0,
        api=api,
        kind=Stack,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )
    assert stack.replicas == 0


def test_upscale_stack_with_autoscaling(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    stack = Stack(
        None,
        {
            "metadata": {
                "name": "my-stack",
                "namespace": "my-ns",
                "creationTimestamp": "2018-10-23T21:55:00Z",
                "annotations": {ORIGINAL_REPLICAS_ANNOTATION: 4},
            },
            "spec": {"autoscaler": {"maxReplicas": 4}, "replicas": 0},
        },
    )

    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    assert stack.replicas == 0
    autoscale_resource(
        stack,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="always",
        default_downtime="never",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=True,
        max_retries_on_conflict=0,
        api=api,
        kind=Stack,
        enable_events=False,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )
    assert stack.obj["spec"]["replicas"] is None
    assert stack.replicas == 4
    assert stack.annotations[ORIGINAL_REPLICAS_ANNOTATION] is None


def test_downscale_hpa_with_autoscaling(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    hpa = HorizontalPodAutoscaler(
        None,
        {
            "metadata": {
                "name": "my-hpa",
                "namespace": "my-ns",
                "creationTimestamp": "2018-10-23T21:55:00Z",
                "annotations": {DOWNTIME_REPLICAS_ANNOTATION: str(1)},
            },
            "spec": {"minReplicas": 4},
        },
    )
    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    autoscale_resource(
        hpa,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=True,
        max_retries_on_conflict=0,
        api=api,
        kind=HorizontalPodAutoscaler,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )
    assert hpa.obj["spec"]["minReplicas"] == 1
    assert hpa.obj["metadata"]["annotations"][ORIGINAL_REPLICAS_ANNOTATION] == str(4)

def test_downscale_hpa_wrong_annotation_value_with_autoscaling(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    hpa = HorizontalPodAutoscaler(
        None,
        {
            "metadata": {
                "name": "my-hpa",
                "namespace": "my-ns",
                "creationTimestamp": "2018-10-23T21:55:00Z",
                "annotations": {DOWNTIME_REPLICAS_ANNOTATION: "3%"},
            },
            "spec": {"minReplicas": 4},
        },
    )
    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    autoscale_resource(
        hpa,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=True,
        max_retries_on_conflict=0,
        api=api,
        kind=HorizontalPodAutoscaler,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )

    #if the DOWNTIME_REPLICAS_ANNOTATION has a percentage value on non pdb objects, they will be skipped
    assert hpa.obj["spec"]["minReplicas"] == 4


def test_upscale_hpa_with_autoscaling(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    hpa = HorizontalPodAutoscaler(
        None,
        {
            "metadata": {
                "name": "my-hpa",
                "namespace": "my-ns",
                "creationTimestamp": "2018-10-23T21:55:00Z",
                "annotations": {
                    DOWNTIME_REPLICAS_ANNOTATION: str(1),
                    ORIGINAL_REPLICAS_ANNOTATION: str(4),
                },
            },
            "spec": {"minReplicas": 1},
        },
    )
    now = datetime.strptime("2018-10-23T22:15:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    autoscale_resource(
        hpa,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="always",
        default_downtime="never",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=True,
        max_retries_on_conflict=0,
        api=api,
        kind=HorizontalPodAutoscaler,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )

    assert hpa.obj["spec"]["minReplicas"] == 4
    assert hpa.obj["metadata"]["annotations"][ORIGINAL_REPLICAS_ANNOTATION] is None


def test_downscale_pdb_minavailable_with_autoscaling(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    pdb = PodDisruptionBudget(
        None,
        {
            "metadata": {
                "name": "my-pdb",
                "namespace": "my-ns",
                "creationTimestamp": "2018-10-23T21:55:00Z",
                "annotations": {DOWNTIME_REPLICAS_ANNOTATION: str(1)},
            },
            "spec": {"minAvailable": 4},
        },
    )
    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    autoscale_resource(
        pdb,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=True,
        max_retries_on_conflict=0,
        api=api,
        kind=PodDisruptionBudget,
        now=now,
    )
    assert pdb.obj["spec"]["minAvailable"] == 1
    assert pdb.obj["metadata"]["annotations"][ORIGINAL_REPLICAS_ANNOTATION] == str(4)


def test_upscale_pdb_minavailable_with_autoscaling(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    pdb = PodDisruptionBudget(
        None,
        {
            "metadata": {
                "name": "my-pdb",
                "namespace": "my-ns",
                "creationTimestamp": "2018-10-23T21:55:00Z",
                "annotations": {
                    DOWNTIME_REPLICAS_ANNOTATION: str(1),
                    ORIGINAL_REPLICAS_ANNOTATION: str(4),
                },
            },
            "spec": {"minAvailable": 1},
        },
    )
    now = datetime.strptime("2018-10-23T22:15:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    autoscale_resource(
        pdb,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="always",
        default_downtime="never",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=True,
        max_retries_on_conflict=0,
        api=api,
        kind=PodDisruptionBudget,
        now=now,
    )
    assert pdb.obj["spec"]["minAvailable"] == 4
    assert pdb.obj["metadata"]["annotations"][ORIGINAL_REPLICAS_ANNOTATION] is None


def test_downscale_pdb_maxunavailable_with_autoscaling(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    pdb = PodDisruptionBudget(
        None,
        {
            "metadata": {
                "name": "my-pdb",
                "namespace": "my-ns",
                "creationTimestamp": "2018-10-23T21:55:00Z",
                "annotations": {DOWNTIME_REPLICAS_ANNOTATION: str(1)},
            },
            "spec": {"maxUnavailable": 4},
        },
    )
    now = datetime.strptime("2018-10-23T21:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    autoscale_resource(
        pdb,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=True,
        max_retries_on_conflict=0,
        api=api,
        kind=PodDisruptionBudget,
        now=now,
    )
    assert pdb.obj["spec"]["maxUnavailable"] == 1
    assert pdb.obj["metadata"]["annotations"][ORIGINAL_REPLICAS_ANNOTATION] == str(4)


def test_upscale_pdb_maxunavailable_with_autoscaling(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    pdb = PodDisruptionBudget(
        None,
        {
            "metadata": {
                "name": "my-pdb",
                "namespace": "my-ns",
                "creationTimestamp": "2018-10-23T21:55:00Z",
                "annotations": {
                    DOWNTIME_REPLICAS_ANNOTATION: str(1),
                    ORIGINAL_REPLICAS_ANNOTATION: str(4),
                },
            },
            "spec": {"maxUnavailable": 1},
        },
    )
    now = datetime.strptime("2018-10-23T22:15:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    autoscale_resource(
        pdb,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="always",
        default_downtime="never",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=True,
        max_retries_on_conflict=0,
        api=api,
        kind=PodDisruptionBudget,
        now=now,
    )
    assert pdb.obj["spec"]["maxUnavailable"] == 4
    assert pdb.obj["metadata"]["annotations"][ORIGINAL_REPLICAS_ANNOTATION] is None


def test_downscale_daemonset_with_autoscaling(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    ds = DaemonSet(
        None,
        {
            "metadata": {
                "name": "daemonset-1",
                "namespace": "default",
                "creationTimestamp": "2018-10-23T21:55:00Z",
            },
            "spec": {"template": {"spec": {}}},
        },
    )
    now = datetime.strptime("2018-10-23T22:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    autoscale_resource(
        ds,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=True,
        max_retries_on_conflict=0,
        api=api,
        kind=DaemonSet,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )

    assert (
        ds.obj["spec"]["template"]["spec"]["nodeSelector"][
            "kube-downscaler-non-existent"
        ]
        == "true"
    )


def test_upscale_daemonset_with_autoscaling(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    ds = DaemonSet(
        None,
        {
            "metadata": {
                "name": "daemonset-1",
                "namespace": "default",
                "creationTimestamp": "2018-10-23T21:55:00Z",
                "annotations": {ORIGINAL_REPLICAS_ANNOTATION: "1"},
            },
            "spec": {
                "template": {
                    "spec": {"nodeSelector": {"kube-downscaler-non-existent": "true"}}
                }
            },
        },
    )
    print("\n" + str(ds.obj) + "\n")
    now = datetime.strptime("2018-10-23T22:25:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    autoscale_resource(
        ds,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="always",
        default_downtime="never",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=True,
        max_retries_on_conflict=0,
        api=api,
        kind=DaemonSet,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )

    assert (
        ds.obj["spec"]["template"]["spec"]["nodeSelector"][
            "kube-downscaler-non-existent"
        ]
        is None
    )


def test_downscale_scaledobject_with_pause_annotation_already_present(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    # Create a ScaledObject with the annotation present
    so = ScaledObject(
        None,
        {
            "metadata": {
                "name": "scaledobject-1",
                "namespace": "default",
                "creationTimestamp": "2023-08-21T10:00:00Z",
                "annotations": {"autoscaling.keda.sh/paused-replicas": "3"},
            },
            "spec": {},
        },
    )

    now = datetime.strptime("2023-08-21T10:30:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )

    autoscale_resource(
        so,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=True,
        max_retries_on_conflict=0,
        api=api,
        kind=ScaledObject,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )

    # Check if the annotations have been correctly updated
    assert so.annotations[ScaledObject.keda_pause_annotation] == "0"
    assert so.replicas == 0


def test_upscale_scaledobject_with_pause_annotation_already_present(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    so = ScaledObject(
        None,
        {
            "metadata": {
                "name": "scaledobject-1",
                "namespace": "default",
                "creationTimestamp": "2023-08-21T10:00:00Z",
                "annotations": {
                    "autoscaling.keda.sh/paused-replicas": "0",  # Paused replicas
                    "downscaler/original-pause-replicas": "3",  # Original replicas before pause
                    "downscaler/original-replicas": "3",  # Keeping track of original replicas
                },
            },
            "spec": {},
        },
    )

    now = datetime.strptime("2023-08-21T10:30:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )

    autoscale_resource(
        so,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="always",
        default_downtime="never",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=True,
        max_retries_on_conflict=0,
        api=api,
        kind=ScaledObject,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )

    # Check if the annotations have been correctly updated for the upscale operation
    assert so.annotations[ScaledObject.keda_pause_annotation] == "3"
    assert so.replicas == 3
    assert (
        so.annotations.get(ScaledObject.last_keda_pause_annotation_if_present) is None
    )


def test_downscale_scaledobject_without_keda_pause_annotation(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    so = ScaledObject(
        None,
        {
            "metadata": {
                "name": "scaledobject-1",
                "namespace": "default",
                "creationTimestamp": "2023-08-21T10:00:00Z",
                "annotations": {},
            },
        },
    )

    now = datetime.strptime("2023-08-21T10:30:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )

    autoscale_resource(
        so,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=True,
        max_retries_on_conflict=0,
        api=api,
        kind=ScaledObject,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )

    # Check if the annotations have been correctly updated
    assert so.annotations[ScaledObject.keda_pause_annotation] == "0"
    assert (
        so.annotations.get(ScaledObject.last_keda_pause_annotation_if_present) is None
    )
    assert so.replicas == 0


def test_upscale_scaledobject_without_keda_pause_annotation(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    so = ScaledObject(
        None,
        {
            "metadata": {
                "name": "scaledobject-1",
                "namespace": "default",
                "creationTimestamp": "2023-08-21T10:00:00Z",
                "annotations": {
                    "autoscaling.keda.sh/paused-replicas": "0",
                    "downscaler/original-replicas": "3",
                },
            },
        },
    )

    now = datetime.strptime("2023-08-21T10:30:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )

    autoscale_resource(
        so,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="always",
        default_downtime="never",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=True,
        max_retries_on_conflict=0,
        api=api,
        kind=ScaledObject,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )

    # Check if the annotations have been correctly updated for the upscale operation
    assert so.annotations[ScaledObject.keda_pause_annotation] is None
    assert (
        so.annotations.get(ScaledObject.last_keda_pause_annotation_if_present) is None
    )
    assert so.replicas == -1


def test_downscale_resource_concurrently_modified(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )

    # Mock HTTPError to simulate conflict
    http_error = HTTPError(
        409,
        "Operation cannot be fulfilled on daemonsets.apps "
        '"daemonset-1": the object has been modified; '
        "please apply your changes to the latest version and try again",
    )

    # Simulate update behavior: conflict on first call, success on second
    api.patch.side_effect = [http_error, None]  # First attempt raises, second succeeds

    # Create the DaemonSet mock
    ds = DaemonSet(
        api,
        {
            "metadata": {
                "name": "daemonset-1",
                "namespace": "default",
                "creationTimestamp": "2018-10-23T21:55:00Z",
            },
            "spec": {"template": {"spec": {}}},
        },
    )

    # Replace update method to track calls
    ds.update = MagicMock(
        side_effect=[http_error, None]
    )  # Simulate conflict and success

    # Mock get_resource with MagicMock
    mock_get_resource = MagicMock(return_value=ds)
    monkeypatch.setattr("kube_downscaler.scaler.get_resource", mock_get_resource)

    # Define time
    now = datetime.strptime("2018-10-23T22:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )

    autoscale_resource(
        ds,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=False,
        max_retries_on_conflict=1,  # 1 Retry Allowed
        api=api,
        kind=DaemonSet,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )

    # Assert the kube_downscaler.scaler.get_resource method was called at least once to retrieve the refreshed resource
    assert mock_get_resource.call_count == 1


def test_downscale_resource_concurrently_modified_without_retries_allowed(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )

    # Mock HTTPError to simulate conflict
    http_error = HTTPError(
        409,
        "Operation cannot be fulfilled on daemonsets.apps "
        '"daemonset-1": the object has been modified; '
        "please apply your changes to the latest version and try again",
    )

    # Simulate update behavior: conflict on first call, success on second
    api.patch.side_effect = [http_error, None]  # First attempt raises, second succeeds

    ds = DaemonSet(
        api,
        {
            "metadata": {
                "name": "daemonset-1",
                "namespace": "default",
                "creationTimestamp": "2018-10-23T21:55:00Z",
            },
            "spec": {"template": {"spec": {}}},
        },
    )

    # Mock get_resource with MagicMock
    mock_get_resource = MagicMock(return_value=ds)
    monkeypatch.setattr("kube_downscaler.scaler.get_resource", mock_get_resource)

    now = datetime.strptime("2018-10-23T22:56:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )

    autoscale_resource(
        ds,
        upscale_target_only=False,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        forced_uptime=False,
        forced_downtime=False,
        dry_run=False,
        max_retries_on_conflict=0,  # No Retries Allowed
        api=api,
        kind=DaemonSet,
        now=now,
        matching_labels=frozenset([re.compile("")]),
    )

    # Assert the kube_downscaler.scaler.get_resource method was not called at all (meaning no retry was performed)
    assert mock_get_resource.call_count == 0
