import datetime
import json
import re
from unittest.mock import MagicMock, patch, PropertyMock

from kube_downscaler.resources.policy import KubeDownscalerJobsPolicy
from kube_downscaler.scaler import DOWNTIME_REPLICAS_ANNOTATION
from kube_downscaler.scaler import EXCLUDE_ANNOTATION
from kube_downscaler.scaler import ORIGINAL_REPLICAS_ANNOTATION
from kube_downscaler.scaler import scale
from kube_downscaler.scaler import autoscale_jobs
from kube_downscaler.scaler import scale_down_jobs
from kube_downscaler.scaler import scale_up_jobs


def test_scaler_always_up(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "deployments":
            data = {
                "items": [
                    {
                        "metadata": {"name": "deploy-1", "namespace": "ns-1"},
                        "spec": {"replicas": 1},
                    }
                ]
            }
        elif url == "statefulsets":
            data = {"items": []}
        elif url == "stacks":
            data = {"items": []}
        elif url == "cronjobs":
            data = {"items": []}
        elif url == "namespaces/ns-1":
            data = {"metadata": {}}
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["statefulsets", "deployments", "stacks", "cronjobs"])
    scale(
        namespace=None,
        upscale_period="never",
        downscale_period="never",
        default_uptime="always",
        default_downtime="never",
        include_resources=include_resources,
        exclude_namespaces=[],
        exclude_deployments=[],
        dry_run=False,
        grace_period=300,
        admission_controller="",
        downtime_replicas=0,
        enable_events=False,
    )

    api.patch.assert_not_called()


def test_scaler_namespace_excluded(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "deployments":
            data = {
                "items": [
                    {
                        "metadata": {
                            "name": "sysdep-1",
                            "namespace": "system-ns",
                            "creationTimestamp": "2019-03-01T16:38:00Z",
                        },
                        "spec": {"replicas": 1},
                    },
                    {
                        "metadata": {
                            "name": "deploy-2",
                            "namespace": "default",
                            "creationTimestamp": "2019-03-01T16:38:00Z",
                        },
                        "spec": {"replicas": 2},
                    },
                ]
            }
        elif url == "namespaces/default":
            data = {"metadata": {}}
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["deployments"])
    scale(
        namespace=None,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        include_resources=include_resources,
        exclude_namespaces=[re.compile("system-ns")],
        exclude_deployments=[],
        dry_run=False,
        matching_labels=frozenset([re.compile("")]),
        grace_period=300,
        admission_controller="",
        downtime_replicas=0,
        enable_events=False,
    )

    assert api.patch.call_count == 1

    # make sure that deploy-2 was updated (namespace of sysdep-1 was excluded)
    patch_data = {
        "metadata": {
            "name": "deploy-2",
            "namespace": "default",
            "creationTimestamp": "2019-03-01T16:38:00Z",
            "annotations": {ORIGINAL_REPLICAS_ANNOTATION: "2"},
        },
        "spec": {"replicas": 0},
    }
    assert api.patch.call_args[1]["url"] == "/deployments/deploy-2"
    assert json.loads(api.patch.call_args[1]["data"]) == patch_data


def test_scaler_namespace_excluded_regex(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "deployments":
            data = {
                "items": [
                    {
                        "metadata": {
                            "name": "sysdep-1",
                            "namespace": "system-ns",
                            "creationTimestamp": "2019-03-01T16:38:00Z",
                        },
                        "spec": {"replicas": 1},
                    },
                    {
                        "metadata": {
                            "name": "deploy-2",
                            "namespace": "default",
                            "creationTimestamp": "2019-03-01T16:38:00Z",
                        },
                        "spec": {"replicas": 2},
                    },
                ]
            }
        elif url == "namespaces/default":
            data = {"metadata": {}}
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["deployments"])
    scale(
        namespace=None,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        include_resources=include_resources,
        exclude_namespaces=[
            re.compile("foo.*"),
            re.compile("syst?em-.*"),
            re.compile("def"),
        ],
        exclude_deployments=[],
        matching_labels=frozenset([re.compile("")]),
        dry_run=False,
        grace_period=300,
        admission_controller="",
        downtime_replicas=0,
        enable_events=False,
    )

    assert api.patch.call_count == 1

    # make sure that deploy-2 was updated (namespace of sysdep-1 was excluded)
    patch_data = {
        "metadata": {
            "name": "deploy-2",
            "namespace": "default",
            "creationTimestamp": "2019-03-01T16:38:00Z",
            "annotations": {ORIGINAL_REPLICAS_ANNOTATION: "2"},
        },
        "spec": {"replicas": 0},
    }
    assert api.patch.call_args[1]["url"] == "/deployments/deploy-2"
    assert json.loads(api.patch.call_args[1]["data"]) == patch_data


def test_scaler_namespace_excluded_via_annotation(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "deployments":
            data = {
                "items": [
                    {
                        "metadata": {
                            "name": "deploy-1",
                            "namespace": "ns-1",
                            "creationTimestamp": "2019-03-01T16:38:00Z",
                        },
                        "spec": {"replicas": 1},
                    },
                    {
                        "metadata": {
                            "name": "deploy-2",
                            "namespace": "ns-2",
                            "creationTimestamp": "2019-03-01T16:38:00Z",
                        },
                        "spec": {"replicas": 2},
                    },
                ]
            }
        elif url == "namespaces/ns-1":
            data = {"metadata": {"annotations": {"downscaler/exclude": "true"}}}
        elif url == "namespaces/ns-2":
            data = {"metadata": {}}
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["deployments"])
    scale(
        namespace=None,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        include_resources=include_resources,
        exclude_namespaces=[],
        exclude_deployments=[],
        matching_labels=frozenset([re.compile("")]),
        dry_run=False,
        grace_period=300,
        admission_controller="",
        downtime_replicas=0,
        enable_events=False,
    )

    assert api.patch.call_count == 1

    # make sure that deploy-2 was updated (deploy-1 was excluded via annotation on ns-1)
    patch_data = {
        "metadata": {
            "name": "deploy-2",
            "namespace": "ns-2",
            "creationTimestamp": "2019-03-01T16:38:00Z",
            "annotations": {ORIGINAL_REPLICAS_ANNOTATION: "2"},
        },
        "spec": {"replicas": 0},
    }
    assert api.patch.call_args[1]["url"] == "/deployments/deploy-2"
    assert json.loads(api.patch.call_args[1]["data"]) == patch_data


def test_scaler_down_to(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.add_event", MagicMock(return_value=None)
    )
    SCALE_TO = 1

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "deployments":
            data = {
                "items": [
                    {
                        "metadata": {
                            "name": "deploy-1",
                            "namespace": "default",
                            "creationTimestamp": "2019-03-01T16:38:00Z",
                            "annotations": {DOWNTIME_REPLICAS_ANNOTATION: SCALE_TO},
                        },
                        "spec": {"replicas": 5},
                    },
                ]
            }
        elif url == "namespaces/default":
            data = {"metadata": {}}
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["deployments"])
    scale(
        namespace=None,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        include_resources=include_resources,
        exclude_namespaces=[],
        exclude_deployments=[],
        matching_labels=frozenset([re.compile("")]),
        dry_run=False,
        grace_period=300,
        admission_controller="",
        downtime_replicas=0,
        enable_events=True,
    )

    assert api.patch.call_count == 1
    assert api.patch.call_args[1]["url"] == "/deployments/deploy-1"
    assert json.loads(api.patch.call_args[1]["data"])["spec"]["replicas"] == SCALE_TO


def test_scaler_down_to_upscale(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.add_event", MagicMock(return_value=None)
    )
    SCALE_TO = 1
    ORIGINAL = 3

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "deployments":
            data = {
                "items": [
                    {
                        "metadata": {
                            "name": "deploy-1",
                            "namespace": "default",
                            "creationTimestamp": "2019-03-01T16:38:00Z",
                            "annotations": {
                                DOWNTIME_REPLICAS_ANNOTATION: SCALE_TO,
                                ORIGINAL_REPLICAS_ANNOTATION: ORIGINAL,
                            },
                        },
                        "spec": {"replicas": SCALE_TO},
                    },
                ]
            }
        elif url == "namespaces/default":
            data = {"metadata": {}}
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["deployments"])
    scale(
        namespace=None,
        upscale_period="never",
        downscale_period="never",
        default_uptime="always",
        default_downtime="never",
        include_resources=include_resources,
        exclude_namespaces=[],
        exclude_deployments=[],
        matching_labels=frozenset([re.compile("")]),
        dry_run=False,
        grace_period=300,
        admission_controller="",
        downtime_replicas=0,
        enable_events=True,
    )

    assert api.patch.call_count == 1
    assert api.patch.call_args[1]["url"] == "/deployments/deploy-1"
    assert json.loads(api.patch.call_args[1]["data"])["spec"]["replicas"] == ORIGINAL
    assert not json.loads(api.patch.call_args[1]["data"])["metadata"]["annotations"][
        ORIGINAL_REPLICAS_ANNOTATION
    ]


def test_scaler_upscale_on_exclude(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    ORIGINAL_REPLICAS = 2

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "deployments":
            data = {
                "items": [
                    {
                        "metadata": {
                            "name": "deploy-1",
                            "namespace": "default",
                            "annotations": {
                                EXCLUDE_ANNOTATION: "true",
                                ORIGINAL_REPLICAS_ANNOTATION: ORIGINAL_REPLICAS,
                            },
                        },
                        "spec": {"replicas": 0},
                    },
                ]
            }
        elif url == "namespaces/default":
            data = {"metadata": {}}
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["deployments"])
    scale(
        namespace=None,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        include_resources=include_resources,
        exclude_namespaces=[],
        exclude_deployments=[],
        matching_labels=frozenset([re.compile("")]),
        dry_run=False,
        grace_period=300,
        admission_controller="",
        downtime_replicas=0,
        enable_events=False,
    )

    assert api.patch.call_count == 1
    assert api.patch.call_args[1]["url"] == "/deployments/deploy-1"
    assert (
        json.loads(api.patch.call_args[1]["data"])["spec"]["replicas"]
        == ORIGINAL_REPLICAS
    )
    assert not json.loads(api.patch.call_args[1]["data"])["metadata"]["annotations"][
        ORIGINAL_REPLICAS_ANNOTATION
    ]


def test_scaler_upscale_on_exclude_namespace(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    ORIGINAL_REPLICAS = 2

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "deployments":
            data = {
                "items": [
                    {
                        "metadata": {
                            "name": "deploy-1",
                            "namespace": "default",
                            "annotations": {
                                ORIGINAL_REPLICAS_ANNOTATION: ORIGINAL_REPLICAS,
                            },
                        },
                        "spec": {"replicas": 0},
                    },
                ]
            }
        elif url == "namespaces/default":
            data = {"metadata": {"annotations": {EXCLUDE_ANNOTATION: "true"}}}
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["deployments"])
    scale(
        namespace=None,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        include_resources=include_resources,
        exclude_namespaces=[],
        exclude_deployments=[],
        matching_labels=frozenset([re.compile("")]),
        dry_run=False,
        grace_period=300,
        admission_controller="",
        downtime_replicas=0,
        enable_events=False,
    )

    assert api.patch.call_count == 1
    assert api.patch.call_args[1]["url"] == "/deployments/deploy-1"
    assert (
        json.loads(api.patch.call_args[1]["data"])["spec"]["replicas"]
        == ORIGINAL_REPLICAS
    )
    assert not json.loads(api.patch.call_args[1]["data"])["metadata"]["annotations"][
        ORIGINAL_REPLICAS_ANNOTATION
    ]


def test_scaler_always_upscale(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "deployments":
            data = {
                "items": [
                    {
                        "metadata": {"name": "deploy-1", "namespace": "ns-1"},
                        "spec": {"replicas": 1},
                    }
                ]
            }
        elif url == "statefulsets":
            data = {"items": []}
        elif url == "stacks":
            data = {"items": []}
        elif url == "namespaces/ns-1":
            data = {"metadata": {}}
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["statefulsets", "deployments", "stacks"])
    scale(
        namespace=None,
        upscale_period="always",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        include_resources=include_resources,
        exclude_namespaces=[],
        exclude_deployments=[],
        matching_labels=frozenset([re.compile("")]),
        dry_run=False,
        grace_period=300,
        admission_controller="",
        downtime_replicas=0,
        enable_events=False,
    )

    api.patch.assert_not_called()


def test_scaler_namespace_annotation_replicas(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    SCALE_TO = 3

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "deployments":
            data = {
                "items": [
                    {
                        "metadata": {
                            "name": "deploy-1",
                            "namespace": "default",
                            "creationTimestamp": "2019-03-01T16:38:00Z",
                        },
                        "spec": {"replicas": 5},
                    },
                ]
            }
        elif url == "namespaces/default":
            data = {
                "metadata": {"annotations": {"downscaler/downtime-replicas": SCALE_TO}}
            }
            # data = {'metadata': {}}
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["deployments"])
    scale(
        namespace=None,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        include_resources=include_resources,
        exclude_namespaces=[],
        exclude_deployments=[],
        matching_labels=frozenset([re.compile("")]),
        dry_run=False,
        grace_period=300,
        admission_controller="",
        downtime_replicas=0,
        enable_events=False,
    )

    assert api.patch.call_count == 1
    assert api.patch.call_args[1]["url"] == "/deployments/deploy-1"
    assert json.loads(api.patch.call_args[1]["data"])["spec"]["replicas"] == SCALE_TO

def test_scaler_daemonset_suspend(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.add_event", MagicMock(return_value=None)
    )

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "daemonsets":
            data = {
                "items": [
                    {
                        "metadata": {
                            "name": "daemonset-1",
                            "namespace": "default",
                            "creationTimestamp": "2024-02-03T16:38:00Z",
                        },
                        "spec": {
                            "template": {
                                "spec": {
                                }
                            }
                        }
                    },
                ]
            }
        elif url == "namespaces/default":
            data = {"metadata": {"annotations": {"downscaler/uptime": "never"}}}
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["daemonsets"])
    scale(
        namespace=None,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        include_resources=include_resources,
        exclude_namespaces=[],
        exclude_deployments=[],
        admission_controller="",
        dry_run=False,
        grace_period=300,
        downtime_replicas=0,
        enable_events=True,
        matching_labels=frozenset([re.compile("")]),
    )

    assert api.patch.call_count == 1
    assert api.patch.call_args[1]["url"] == "/daemonsets/daemonset-1"

    patch_data = {
        "metadata": {
            "name": "daemonset-1",
            "namespace": "default",
            "creationTimestamp": "2024-02-03T16:38:00Z",
            "annotations": {ORIGINAL_REPLICAS_ANNOTATION: "1"},
        },
        "spec": {
            "template": {
                "spec": {
                    "nodeSelector": {
                        "kube-downscaler-non-existent": "true"
                    }
                }
            }
        }
    }
    assert json.loads(api.patch.call_args[1]["data"]) == patch_data

def test_scaler_daemonset_unsuspend(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.add_event", MagicMock(return_value=None)
    )

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "daemonsets":
            data = {
                "items": [
                    {
                        "metadata": {
                            "name": "daemonset-1",
                            "namespace": "default",
                            "creationTimestamp": "2024-02-03T16:38:00Z",
                            "annotations": {ORIGINAL_REPLICAS_ANNOTATION: "1"},
                        },
                        "spec": {
                            "template": {
                                "spec": {
                                    "nodeSelector": {
                                        "kube-downscaler-non-existent": "true"
                                    }
                                }
                            }
                        }
                    },
                ]
            }
        elif url == "namespaces/default":
            data = {
                "metadata": {
                    "annotations": {
                        "downscaler/uptime": "always",
                        "downscaler/downtime": "never",
                    }
                }
            }
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["daemonsets"])
    scale(
        namespace=None,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        include_resources=include_resources,
        exclude_namespaces=[],
        exclude_deployments=[],
        admission_controller="",
        dry_run=False,
        grace_period=300,
        downtime_replicas=0,
        enable_events=True,
        matching_labels=frozenset([re.compile("")]),
    )

    assert api.patch.call_count == 1
    assert api.patch.call_args[1]["url"] == "/daemonsets/daemonset-1"

    patch_data = {
        "metadata": {
            "name": "daemonset-1",
            "namespace": "default",
            "creationTimestamp": "2024-02-03T16:38:00Z",
            "annotations": {ORIGINAL_REPLICAS_ANNOTATION: None}
        },
        "spec": {
            "template": {
                "spec": {
                    "nodeSelector": {
                        "kube-downscaler-non-existent": None
                    }
                }
            }
        },
    }
    assert json.loads(api.patch.call_args[1]["data"]) == patch_data


def test_scaler_cronjob_suspend(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.add_event", MagicMock(return_value=None)
    )

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "cronjobs":
            data = {
                "items": [
                    {
                        "metadata": {
                            "name": "cronjob-1",
                            "namespace": "default",
                            "creationTimestamp": "2019-03-01T16:38:00Z",
                        },
                        "spec": {"suspend": False},
                    },
                ]
            }
        elif url == "namespaces/default":
            data = {"metadata": {"annotations": {"downscaler/uptime": "never"}}}
            # data = {'metadata': {}}
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["cronjobs"])
    scale(
        namespace=None,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        include_resources=include_resources,
        exclude_namespaces=[],
        exclude_deployments=[],
        dry_run=False,
        grace_period=300,
        admission_controller="",
        downtime_replicas=0,
        enable_events=True,
        matching_labels=frozenset([re.compile("")]),
    )

    assert api.patch.call_count == 1
    assert api.patch.call_args[1]["url"] == "/cronjobs/cronjob-1"

    patch_data = {
        "metadata": {
            "name": "cronjob-1",
            "namespace": "default",
            "creationTimestamp": "2019-03-01T16:38:00Z",
            "annotations": {ORIGINAL_REPLICAS_ANNOTATION: "1"},
        },
        "spec": {"suspend": True},
    }
    assert json.loads(api.patch.call_args[1]["data"]) == patch_data


def test_scaler_cronjob_unsuspend(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.add_event", MagicMock(return_value=None)
    )

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "cronjobs":
            data = {
                "items": [
                    {
                        "metadata": {
                            "name": "cronjob-1",
                            "namespace": "default",
                            "creationTimestamp": "2019-03-01T16:38:00Z",
                            "annotations": {ORIGINAL_REPLICAS_ANNOTATION: "1"},
                        },
                        "spec": {"suspend": True},
                    },
                ]
            }
        elif url == "namespaces/default":
            data = {
                "metadata": {
                    "annotations": {
                        "downscaler/uptime": "always",
                        "downscaler/downtime": "never",
                    }
                }
            }
            # data = {'metadata': {}}
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["cronjobs"])
    scale(
        namespace=None,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        include_resources=include_resources,
        exclude_namespaces=[],
        exclude_deployments=[],
        matching_labels=frozenset([re.compile("")]),
        dry_run=False,
        grace_period=300,
        admission_controller="",
        downtime_replicas=0,
        enable_events=True,
    )

    assert api.patch.call_count == 1
    assert api.patch.call_args[1]["url"] == "/cronjobs/cronjob-1"

    patch_data = {
        "metadata": {
            "name": "cronjob-1",
            "namespace": "default",
            "creationTimestamp": "2019-03-01T16:38:00Z",
            "annotations": {ORIGINAL_REPLICAS_ANNOTATION: None},
        },
        "spec": {"suspend": False},
    }
    assert json.loads(api.patch.call_args[1]["data"]) == patch_data


def test_scaler_downscale_period_no_error(monkeypatch, caplog):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "cronjobs":
            data = {
                "items": [
                    {
                        "metadata": {
                            "name": "cronjob-1",
                            "namespace": "default",
                            "creationTimestamp": "2019-03-01T16:38:00Z",
                            "annotations": {},
                        },
                        "spec": {"suspend": False},
                    },
                ]
            }
        elif url == "namespaces/default":
            data = {"metadata": {}}
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["cronjobs"])
    scale(
        namespace=None,
        upscale_period="never",
        downscale_period="Mon-Tue 19:00-19:00 UTC",
        default_uptime="always",
        default_downtime="never",
        include_resources=include_resources,
        exclude_namespaces=[],
        exclude_deployments=[],
        matching_labels=frozenset([re.compile("")]),
        dry_run=False,
        grace_period=300,
        admission_controller="",
        downtime_replicas=0,
        enable_events=False,
    )

    assert api.patch.call_count == 0
    for record in caplog.records:
        assert record.levelname != "ERROR"


def test_scaler_deployment_excluded_until(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )

    one_day_in_future = datetime.datetime.utcnow() + datetime.timedelta(days=1)

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "deployments":
            data = {
                "items": [
                    {
                        "metadata": {
                            "name": "deploy-1",
                            "namespace": "my-ns",
                            "creationTimestamp": "2020-04-04T16:38:00Z",
                            "annotations": {"downscaler/exclude-until": "2040-01-01"},
                        },
                        "spec": {"replicas": 1},
                    },
                    {
                        "metadata": {
                            "name": "deploy-2",
                            "namespace": "my-ns",
                            "creationTimestamp": "2020-04-04T16:38:00Z",
                            "annotations": {"downscaler/exclude-until": "2020-04-04"},
                        },
                        "spec": {"replicas": 2},
                    },
                    {
                        "metadata": {
                            "name": "deploy-3",
                            "namespace": "my-ns",
                            "creationTimestamp": "2020-04-04T16:38:00Z",
                            "annotations": {
                                "downscaler/exclude-until": one_day_in_future.strftime(
                                    "%Y-%m-%dT%H:%M:%SZ"
                                )
                            },
                        },
                        "spec": {"replicas": 3},
                    },
                ]
            }
        elif url == "namespaces/my-ns":
            data = {"metadata": {}}
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["deployments"])
    scale(
        namespace=None,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        include_resources=include_resources,
        exclude_namespaces=[],
        exclude_deployments=[],
        matching_labels=frozenset([re.compile("")]),
        dry_run=False,
        grace_period=300,
        admission_controller="",
    )

    assert api.patch.call_count == 1

    # make sure that deploy-2 was updated (deploy-1 was excluded via annotation)
    patch_data = {
        "metadata": {
            "name": "deploy-2",
            "namespace": "my-ns",
            "creationTimestamp": "2020-04-04T16:38:00Z",
            "annotations": {
                ORIGINAL_REPLICAS_ANNOTATION: "2",
                "downscaler/exclude-until": "2020-04-04",
            },
        },
        "spec": {"replicas": 0},
    }
    assert api.patch.call_args[1]["url"] == "/deployments/deploy-2"
    assert json.loads(api.patch.call_args[1]["data"]) == patch_data


def test_scaler_namespace_excluded_until(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "deployments":
            data = {
                "items": [
                    {
                        "metadata": {
                            "name": "deploy-1",
                            "namespace": "ns-1",
                            "creationTimestamp": "2019-03-01T16:38:00Z",
                        },
                        "spec": {"replicas": 1},
                    },
                    {
                        "metadata": {
                            "name": "deploy-2",
                            "namespace": "ns-2",
                            "creationTimestamp": "2019-03-01T16:38:00Z",
                        },
                        "spec": {"replicas": 2},
                    },
                ]
            }
        elif url == "namespaces/ns-1":
            data = {
                "metadata": {
                    "annotations": {"downscaler/exclude-until": "2032-01-01T02:20"}
                }
            }
        elif url == "namespaces/ns-2":
            data = {"metadata": {}}
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["deployments"])
    scale(
        namespace=None,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        include_resources=include_resources,
        exclude_namespaces=[],
        exclude_deployments=[],
        matching_labels=frozenset([re.compile("")]),
        dry_run=False,
        grace_period=300,
        admission_controller="",
        downtime_replicas=0,
    )

    assert api.patch.call_count == 1

    # make sure that deploy-2 was updated (deploy-1 was excluded via annotation on ns-1)
    patch_data = {
        "metadata": {
            "name": "deploy-2",
            "namespace": "ns-2",
            "creationTimestamp": "2019-03-01T16:38:00Z",
            "annotations": {ORIGINAL_REPLICAS_ANNOTATION: "2"},
        },
        "spec": {"replicas": 0},
    }
    assert api.patch.call_args[1]["url"] == "/deployments/deploy-2"
    assert json.loads(api.patch.call_args[1]["data"]) == patch_data


def test_scaler_name_excluded(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "deployments":
            data = {
                "items": [
                    {
                        "metadata": {
                            "name": "sysdep-1",
                            "namespace": "system-ns",
                            "creationTimestamp": "2019-03-01T16:38:00Z",
                        },
                        "spec": {"replicas": 1},
                    },
                    {
                        "metadata": {
                            "name": "deploy-2",
                            "namespace": "default",
                            "creationTimestamp": "2019-03-01T16:38:00Z",
                        },
                        "spec": {"replicas": 2},
                    },
                ]
            }
        elif url == "namespaces/default":
            data = {"metadata": {}}
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["deployments"])
    scale(
        namespace=None,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        include_resources=include_resources,
        exclude_namespaces=[],
        exclude_deployments=["sysdep-1"],
        matching_labels=frozenset([re.compile("")]),
        dry_run=False,
        grace_period=300,
        admission_controller="",
    )

    assert api.patch.call_count == 1

    # make sure that deploy-2 was updated (sysdep-1 was excluded)
    patch_data = {
        "metadata": {
            "name": "deploy-2",
            "namespace": "default",
            "creationTimestamp": "2019-03-01T16:38:00Z",
            "annotations": {ORIGINAL_REPLICAS_ANNOTATION: "2"},
        },
        "spec": {"replicas": 0},
    }
    assert api.patch.call_args[1]["url"] == "/deployments/deploy-2"
    assert json.loads(api.patch.call_args[1]["data"]) == patch_data


def test_scaler_namespace_force_uptime_true(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "deployments":
            data = {
                "items": [
                    {
                        "metadata": {
                            "name": "deploy-1",
                            "namespace": "ns-1",
                            "creationTimestamp": "2019-03-01T16:38:00Z",
                        },
                        "spec": {"replicas": 1},
                    },
                ]
            }
        elif url == "namespaces/ns-1":
            data = {"metadata": {"annotations": {"downscaler/force-uptime": "true"}}}
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["deployments"])
    scale(
        namespace=None,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        include_resources=include_resources,
        exclude_namespaces=[],
        exclude_deployments=[],
        matching_labels=frozenset([re.compile("")]),
        dry_run=False,
        grace_period=300,
        admission_controller="",
    )

    assert api.patch.call_count == 0


def test_scaler_namespace_force_uptime_false(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "deployments":
            data = {
                "items": [
                    {
                        "metadata": {
                            "name": "deploy-1",
                            "namespace": "ns-1",
                            "creationTimestamp": "2019-03-01T16:38:00Z",
                        },
                        "spec": {"replicas": 1},
                    },
                ]
            }
        elif url == "namespaces/ns-1":
            data = {"metadata": {"annotations": {"downscaler/force-uptime": "false"}}}
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["deployments"])
    scale(
        namespace=None,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        include_resources=include_resources,
        exclude_namespaces=[],
        exclude_deployments=[],
        matching_labels=frozenset([re.compile("")]),
        dry_run=False,
        grace_period=300,
        admission_controller="",
    )

    assert api.patch.call_count == 1

    # make sure that deploy-1 was updated
    patch_data = {
        "metadata": {
            "name": "deploy-1",
            "namespace": "ns-1",
            "creationTimestamp": "2019-03-01T16:38:00Z",
            "annotations": {ORIGINAL_REPLICAS_ANNOTATION: "1"},
        },
        "spec": {"replicas": 0},
    }
    assert api.patch.call_args[1]["url"] == "/deployments/deploy-1"
    assert json.loads(api.patch.call_args[1]["data"]) == patch_data


def test_scaler_namespace_force_uptime_period(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    ORIGINAL_REPLICAS = 2

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "deployments":
            data = {
                "items": [
                    {
                        "metadata": {
                            "name": "deploy-1",
                            "namespace": "ns-1",
                            "creationTimestamp": "2019-03-01T16:38:00Z",
                            "annotations": {
                                ORIGINAL_REPLICAS_ANNOTATION: ORIGINAL_REPLICAS,
                            },
                        },
                        "spec": {"replicas": 0},
                    },
                    {
                        "metadata": {
                            "name": "deploy-2",
                            "namespace": "ns-2",
                            "creationTimestamp": "2019-03-01T16:38:00Z",
                            "annotations": {
                                ORIGINAL_REPLICAS_ANNOTATION: ORIGINAL_REPLICAS,
                            },
                        },
                        "spec": {"replicas": 0},
                    },
                    {
                        "metadata": {
                            "name": "deploy-3",
                            "namespace": "ns-3",
                            "creationTimestamp": "2019-03-01T16:38:00Z",
                            "annotations": {
                                ORIGINAL_REPLICAS_ANNOTATION: ORIGINAL_REPLICAS,
                            },
                        },
                        "spec": {"replicas": 0},
                    },
                ]
            }
        elif url == "namespaces/ns-1":
            # past period
            data = {
                "metadata": {
                    "annotations": {
                        "downscaler/force-uptime": "2020-04-04T16:00:00+00:00-2020-04-05T16:00:00+00:00"
                    }
                }
            }
        elif url == "namespaces/ns-2":
            # current period
            data = {
                "metadata": {
                    "annotations": {
                        "downscaler/force-uptime": "2020-04-04T16:00:00+00:00-2040-04-05T16:00:00+00:00"
                    }
                }
            }
        elif url == "namespaces/ns-3":
            # future period
            data = {
                "metadata": {
                    "annotations": {
                        "downscaler/force-uptime": "2040-04-04T16:00:00+00:00-2040-04-05T16:00:00+00:00"
                    }
                }
            }
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["deployments"])
    scale(
        namespace=None,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        include_resources=include_resources,
        exclude_namespaces=[],
        exclude_deployments=[],
        matching_labels=frozenset([re.compile("")]),
        dry_run=False,
        grace_period=300,
        admission_controller="",
    )

    # make sure that deploy-2 was updated
    assert api.patch.call_count == 1
    assert api.patch.call_args[1]["url"] == "/deployments/deploy-2"
    assert (
        json.loads(api.patch.call_args[1]["data"])["spec"]["replicas"]
        == ORIGINAL_REPLICAS
    )
    assert not json.loads(api.patch.call_args[1]["data"])["metadata"]["annotations"][
        ORIGINAL_REPLICAS_ANNOTATION
    ]


def test_scaler_namespace_force_downtime_true(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "deployments":
            data = {
                "items": [
                    {
                        "metadata": {
                            "name": "deploy-1",
                            "namespace": "ns-1",
                            "creationTimestamp": "2019-03-01T16:38:00Z",
                        },
                        "spec": {"replicas": 1},
                    },
                ]
            }
        elif url == "namespaces/ns-1":
            data = {"metadata": {"annotations": {"downscaler/force-downtime": "true"}}}
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["deployments"])
    scale(
        namespace=None,
        upscale_period="never",
        downscale_period="never",
        default_uptime="always",
        default_downtime="never",
        include_resources=include_resources,
        exclude_namespaces=[],
        exclude_deployments=[],
        matching_labels=frozenset([re.compile("")]),
        dry_run=False,
        grace_period=300,
        admission_controller="",
    )

    assert api.patch.call_count == 1


def test_scaler_namespace_force_downtime_false(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "deployments":
            data = {
                "items": [
                    {
                        "metadata": {
                            "name": "deploy-1",
                            "namespace": "ns-1",
                            "creationTimestamp": "2019-03-01T16:38:00Z",
                        },
                        "spec": {"replicas": 1},
                    },
                ]
            }
        elif url == "namespaces/ns-1":
            data = {"metadata": {"annotations": {"downscaler/force-downtime": "false"}}}
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["deployments"])
    scale(
        namespace=None,
        upscale_period="never",
        downscale_period="never",
        default_uptime="always",
        default_downtime="never",
        include_resources=include_resources,
        exclude_namespaces=[],
        exclude_deployments=[],
        matching_labels=frozenset([re.compile("")]),
        dry_run=False,
        grace_period=300,
        admission_controller="",
    )

    assert api.patch.call_count == 0


def test_scaler_namespace_force_uptime_and_downtime_true(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "deployments":
            data = {
                "items": [
                    {
                        "metadata": {
                            "name": "deploy-1",
                            "namespace": "ns-1",
                            "creationTimestamp": "2019-03-01T16:38:00Z",
                        },
                        "spec": {"replicas": 1},
                    },
                ]
            }
        elif url == "namespaces/ns-1":
            data = {
                "metadata": {
                    "annotations": {
                        "downscaler/force-downtime": "true",
                        "downscaler/force-uptime": "true",
                    }
                }
            }
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["deployments"])
    scale(
        namespace=None,
        upscale_period="never",
        downscale_period="never",
        default_uptime="always",
        default_downtime="never",
        include_resources=include_resources,
        exclude_namespaces=[],
        exclude_deployments=[],
        matching_labels=frozenset([re.compile("")]),
        dry_run=False,
        grace_period=300,
        admission_controller="",
    )

    assert api.patch.call_count == 0


def test_scaler_namespace_force_downtime_period(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "deployments":
            data = {
                "items": [
                    {
                        "metadata": {
                            "name": "deploy-1",
                            "namespace": "ns-1",
                            "creationTimestamp": "2019-03-01T16:38:00Z",
                        },
                        "spec": {"replicas": 1},
                    },
                    {
                        "metadata": {
                            "name": "deploy-2",
                            "namespace": "ns-2",
                            "creationTimestamp": "2019-03-01T16:38:00Z",
                        },
                        "spec": {"replicas": 1},
                    },
                    {
                        "metadata": {
                            "name": "deploy-3",
                            "namespace": "ns-3",
                            "creationTimestamp": "2019-03-01T16:38:00Z",
                        },
                        "spec": {"replicas": 1},
                    },
                ]
            }
        elif url == "namespaces/ns-1":
            # past period
            data = {
                "metadata": {
                    "annotations": {
                        "downscaler/force-downtime": "2020-04-04T16:00:00+00:00-2020-04-05T16:00:00+00:00"
                    }
                }
            }
        elif url == "namespaces/ns-2":
            # current period
            data = {
                "metadata": {
                    "annotations": {
                        "downscaler/force-downtime": "2020-04-04T16:00:00+00:00-2040-04-05T16:00:00+00:00"
                    }
                }
            }
        elif url == "namespaces/ns-3":
            # future period
            data = {
                "metadata": {
                    "annotations": {
                        "downscaler/force-downtime": "2040-04-04T16:00:00+00:00-2040-04-05T16:00:00+00:00"
                    }
                }
            }
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["deployments"])
    scale(
        namespace=None,
        upscale_period="never",
        downscale_period="never",
        default_uptime="always",
        default_downtime="never",
        include_resources=include_resources,
        exclude_namespaces=[],
        exclude_deployments=[],
        matching_labels=frozenset([re.compile("")]),
        dry_run=False,
        grace_period=300,
        admission_controller="",
    )

    # make sure that deploy-2 was updated
    assert api.patch.call_count == 1
    assert api.patch.call_args[1]["url"] == "/deployments/deploy-2"
    assert json.loads(api.patch.call_args[1]["data"])["spec"]["replicas"] == 0

@patch("kube_downscaler.scaler.autoscale_jobs_for_namespace")
@patch("kube_downscaler.scaler.Namespace")
@patch("kube_downscaler.scaler.gatekeeper_constraint_template_crd_exist", return_value=False)
def test_autoscale_jobs_gatekeeper_not_installed(
        mock_gatekeeper_exist, mock_namespace, mock_autoscale_jobs_for_namespace
):
    mock_namespace_instance = MagicMock()
    mock_namespace_instance.name = "test-namespace"
    mock_namespace.return_value = mock_namespace_instance

    autoscale_jobs(
        api=None,
        namespace="test-namespace",
        exclude_namespaces=set(),
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        forced_uptime=True,
        matching_labels=set(),
        dry_run=False,
        now=datetime.datetime.now(),
        grace_period=60,
        admission_controller="gatekeeper",
        exclude_names=[],
        enable_events=True,
    )

    assert mock_gatekeeper_exist.called
    mock_autoscale_jobs_for_namespace.assert_not_called()  # autoscale_jobs_for_namespace should not be called


@patch("kube_downscaler.scaler.autoscale_jobs_for_namespace")
@patch("kube_downscaler.scaler.Namespace")
def test_autoscale_jobs_invented_admission_controller(
        mock_namespace, mock_autoscale_jobs_for_namespace
):
    # Mock the Namespace instance
    mock_namespace_instance = MagicMock()
    mock_namespace_instance.name = "test-namespace"
    mock_namespace.return_value = mock_namespace_instance

    autoscale_jobs(
        api=None,
        namespace="test-namespace",
        exclude_namespaces=set(),
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        forced_uptime=True,
        matching_labels=set(),
        dry_run=False,
        now=datetime.datetime.now(),
        grace_period=60,
        admission_controller="invented_admission_controller",
        exclude_names=[],
        enable_events=True,
    )

    mock_autoscale_jobs_for_namespace.assert_not_called()


@patch('kube_downscaler.scaler.KubeDownscalerJobsConstraint.objects', autospec=True)
def test_scale_up_jobs_gatekeeper_policy_not_none(objects_mock):
    api = MagicMock()
    objects_instance_mock = objects_mock.return_value
    objects_instance_mock.get_or_none.return_value = "Not None"

    policy, operation = scale_up_jobs(
        MagicMock(), MagicMock(), "uptime_value", "downtime_value",
        "gatekeeper", False, True
    )

    assert operation == "scale_up"


@patch('kube_downscaler.scaler.KubeDownscalerJobsPolicy.objects', autospec=True)
def test_scale_up_jobs_kyverno_policy_not_none(objects_mock):
    api = MagicMock()
    filter_instance_mock = objects_mock.return_value.filter.return_value
    filter_instance_mock.get_or_none.return_value = "Not None"

    policy, operation = scale_up_jobs(
        MagicMock(),
        MagicMock(),
        "uptime_value",
        "downtime_value",
        "kyverno",
        False,
        True
    )

    assert operation == "scale_up"


@patch('kube_downscaler.scaler.KubeDownscalerJobsConstraint.objects', autospec=True)
def test_scale_up_jobs_gatekeeper_policy_none(objects_mock):
    api = MagicMock()
    objects_instance_mock = objects_mock.return_value
    objects_instance_mock.get_or_none.return_value = None

    policy, operation = scale_up_jobs(
        MagicMock(),
        MagicMock(),
        "uptime_value",
        "downtime_value",
        "gatekeeper",
        False,
        True
    )

    assert operation == "no_scale"

@patch('kube_downscaler.scaler.KubeDownscalerJobsPolicy.objects', autospec=True)
def test_scale_up_jobs_kyverno_policy_none(objects_mock):
    api = MagicMock()
    filter_instance_mock = objects_mock.return_value.filter.return_value
    filter_instance_mock.get_or_none.return_value = None

    policy, operation = scale_up_jobs(
        MagicMock(),
        MagicMock(),
        "uptime_value",
        "downtime_value",
        "kyverno",
        False,
        True
    )

    assert operation == "no_scale"

@patch('kube_downscaler.scaler.KubeDownscalerJobsConstraint.objects', autospec=True)
def test_scale_down_jobs_gatekeeper_policy_not_none(objects_mock):
    api = MagicMock()
    objects_instance_mock = objects_mock.return_value
    objects_instance_mock.get_or_none.return_value = "Not None"

    obj, operation = scale_down_jobs(
        MagicMock(),
        MagicMock(),
        "uptime_value",
        "downtime_value",
        "gatekeeper",
        [],
        frozenset([re.compile("")]),
        False,
        True
    )

    assert operation == "no_scale"


@patch('kube_downscaler.scaler.KubeDownscalerJobsPolicy.objects', autospec=True)
def test_scale_down_jobs_kyverno_policy_not_none(objects_mock):
    api = MagicMock()
    mock_obj = MagicMock()
    type(mock_obj).type = PropertyMock(return_value="with-matching-labels")
    filter_instance_mock = objects_mock.return_value.filter.return_value
    filter_instance_mock.get_or_none.return_value = mock_obj

    obj, operation = scale_down_jobs(
        MagicMock(),
        MagicMock(),
        "uptime_value",
        "downtime_value",
        "kyverno",
        [],
        frozenset([re.compile(".*")]),
        False,
        True
    )

    assert operation == "no_scale"


@patch('kube_downscaler.scaler.KubeDownscalerJobsConstraint.objects', autospec=True)
def test_scale_down_jobs_gatekeeper_policy_none(objects_mock):
    api = MagicMock()
    objects_instance_mock = objects_mock.return_value
    objects_instance_mock.get_or_none.return_value = None

    obj, operation = scale_down_jobs(
        MagicMock(),
        MagicMock(),
        "uptime_value",
        "downtime_value",
        "gatekeeper",
        [],
        frozenset([re.compile("")]),
        False,
        True
    )

    assert operation == "scale_down"

@patch('kube_downscaler.scaler.KubeDownscalerJobsPolicy.objects', autospec=True)
def test_scale_down_jobs_kyverno_policy_none(objects_mock):
    api = MagicMock()
    filter_instance_mock = objects_mock.return_value.filter.return_value
    filter_instance_mock.get_or_none.return_value = None

    obj, operation = scale_down_jobs(
        MagicMock(),
        MagicMock(),
        "uptime_value",
        "downtime_value",
        "kyverno",
        [],
        frozenset([re.compile("")]),
        False,
        True
    )

    assert operation == "scale_down"

def test_scaler_pdb_suspend_max_unavailable(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.add_event", MagicMock(return_value=None)
    )

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "poddisruptionbudgets":
            data = {
                "items": [
                    {
                        "metadata": {
                            "name": "pdb-1",
                            "namespace": "default",
                            "creationTimestamp": "2024-02-03T16:38:00Z",
                        },
                        "spec": {"maxUnavailable": 1}
                    },
                ]
            }
        elif url == "namespaces/default":
            data = {"metadata": {"annotations": {"downscaler/uptime": "never"}}}
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["poddisruptionbudgets"])
    scale(
        namespace=None,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        include_resources=include_resources,
        exclude_namespaces=[],
        exclude_deployments=[],
        admission_controller="",
        dry_run=False,
        grace_period=300,
        downtime_replicas=0,
        enable_events=True,
        matching_labels=frozenset([re.compile("")]),
    )

    assert api.patch.call_count == 1
    assert api.patch.call_args[1]["url"] == "/poddisruptionbudgets/pdb-1"

    patch_data = {
        "metadata": {
            "name": "pdb-1",
            "namespace": "default",
            "creationTimestamp": "2024-02-03T16:38:00Z",
            "annotations": {ORIGINAL_REPLICAS_ANNOTATION: "1"},
        },
        "spec": {"maxUnavailable": 0},
    }
    assert json.loads(api.patch.call_args[1]["data"]) == patch_data

def test_scaler_pdb_unsuspend_max_unavailable(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.add_event", MagicMock(return_value=None)
    )

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "poddisruptionbudgets":
            data = {
                "items": [
                    {
                        "metadata": {
                            "name": "pdb-1",
                            "namespace": "default",
                            "creationTimestamp": "2024-02-03T16:38:00Z",
                            "annotations": {ORIGINAL_REPLICAS_ANNOTATION: "1"},
                        },
                        "spec": {"maxUnavailable": 0}
                    },
                ]
            }
        elif url == "namespaces/default":
            data = {
                "metadata": {
                    "annotations": {
                        "downscaler/uptime": "always",
                        "downscaler/downtime": "never",
                    }
                }
            }
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["poddisruptionbudgets"])
    scale(
        namespace=None,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        include_resources=include_resources,
        exclude_namespaces=[],
        exclude_deployments=[],
        admission_controller="",
        dry_run=False,
        grace_period=300,
        downtime_replicas=0,
        enable_events=True,
        matching_labels=frozenset([re.compile("")]),
    )

    assert api.patch.call_count == 1
    assert api.patch.call_args[1]["url"] == "/poddisruptionbudgets/pdb-1"

    patch_data = {
        "metadata": {
            "name": "pdb-1",
            "namespace": "default",
            "creationTimestamp": "2024-02-03T16:38:00Z",
            "annotations": {ORIGINAL_REPLICAS_ANNOTATION: None}
        },
        "spec": {"maxUnavailable": 1},
    }
    assert json.loads(api.patch.call_args[1]["data"]) == patch_data

def test_scaler_pdb_suspend_min_available(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.add_event", MagicMock(return_value=None)
    )

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "poddisruptionbudgets":
            data = {
                "items": [
                    {
                        "metadata": {
                            "name": "pdb-1",
                            "namespace": "default",
                            "creationTimestamp": "2024-02-03T16:38:00Z",
                        },
                        "spec": {"minAvailable": 1}
                    },
                ]
            }
        elif url == "namespaces/default":
            data = {"metadata": {"annotations": {"downscaler/uptime": "never"}}}
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["poddisruptionbudgets"])
    scale(
        namespace=None,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        include_resources=include_resources,
        exclude_namespaces=[],
        exclude_deployments=[],
        admission_controller="",
        dry_run=False,
        grace_period=300,
        downtime_replicas=0,
        enable_events=True,
        matching_labels=frozenset([re.compile("")]),
    )

    assert api.patch.call_count == 1
    assert api.patch.call_args[1]["url"] == "/poddisruptionbudgets/pdb-1"

    patch_data = {
        "metadata": {
            "name": "pdb-1",
            "namespace": "default",
            "creationTimestamp": "2024-02-03T16:38:00Z",
            "annotations": {ORIGINAL_REPLICAS_ANNOTATION: "1"},
        },
        "spec": {"minAvailable": 0},
    }
    assert json.loads(api.patch.call_args[1]["data"]) == patch_data

def test_scaler_pdb_unsuspend_min_available(monkeypatch):
    api = MagicMock()
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.get_kube_api", MagicMock(return_value=api)
    )
    monkeypatch.setattr(
        "kube_downscaler.scaler.helper.add_event", MagicMock(return_value=None)
    )

    def get(url, version, **kwargs):
        if url == "pods":
            data = {"items": []}
        elif url == "poddisruptionbudgets":
            data = {
                "items": [
                    {
                        "metadata": {
                            "name": "pdb-1",
                            "namespace": "default",
                            "creationTimestamp": "2024-02-03T16:38:00Z",
                            "annotations": {ORIGINAL_REPLICAS_ANNOTATION: "1"},
                        },
                        "spec": {"minAvailable": 0}
                    },
                ]
            }
        elif url == "namespaces/default":
            data = {
                "metadata": {
                    "annotations": {
                        "downscaler/uptime": "always",
                        "downscaler/downtime": "never",
                    }
                }
            }
        else:
            raise Exception(f"unexpected call: {url}, {version}, {kwargs}")

        response = MagicMock()
        response.json.return_value = data
        return response

    api.get = get

    include_resources = frozenset(["poddisruptionbudgets"])
    scale(
        namespace=None,
        upscale_period="never",
        downscale_period="never",
        default_uptime="never",
        default_downtime="always",
        include_resources=include_resources,
        exclude_namespaces=[],
        exclude_deployments=[],
        admission_controller="",
        dry_run=False,
        grace_period=300,
        downtime_replicas=0,
        enable_events=True,
        matching_labels=frozenset([re.compile("")]),
    )

    assert api.patch.call_count == 1
    assert api.patch.call_args[1]["url"] == "/poddisruptionbudgets/pdb-1"

    patch_data = {
        "metadata": {
            "name": "pdb-1",
            "namespace": "default",
            "creationTimestamp": "2024-02-03T16:38:00Z",
            "annotations": {ORIGINAL_REPLICAS_ANNOTATION: None}
        },
        "spec": {"minAvailable": 1},
    }
    assert json.loads(api.patch.call_args[1]["data"]) == patch_data