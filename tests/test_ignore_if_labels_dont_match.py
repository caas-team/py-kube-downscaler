import re
from unittest.mock import MagicMock

import pytest as pytest
from pykube.objects import Deployment
from pykube.objects import NamespacedAPIObject

from kube_downscaler.scaler import ignore_if_labels_dont_match


@pytest.fixture()
def resource():
    api_mock = MagicMock(spec=NamespacedAPIObject, name="APIMock")
    labels_mock = {"metadata": {"labels": {"labelkey": "labelval"}}}
    api_mock.obj = MagicMock(name="APIObjMock")
    deployment = Deployment(api_mock, labels_mock)
    yield deployment


def test_dont_ignore_if_no_labels(resource):
    # for backwards compatibility, if no labels are specified, don't ignore the resource
    assert not ignore_if_labels_dont_match(resource, frozenset())


def test_dont_ignore_if_labels_match(resource):
    assert not ignore_if_labels_dont_match(
        resource, frozenset([re.compile("labelkey=labelval")])
    )


def test_ignore_if_labels_not_matching_value(resource):
    assert ignore_if_labels_dont_match(
        resource, frozenset([re.compile("labelkey=labelval1")])
    )


def test_ignore_if_labels_not_matching_key(resource):
    assert ignore_if_labels_dont_match(
        resource, frozenset([re.compile("labelkey1=labelval")])
    )
