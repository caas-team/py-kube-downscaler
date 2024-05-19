import re
from unittest.mock import MagicMock

from pykube import Deployment
from pykube import StatefulSet
from pykube.objects import NamespacedAPIObject, APIObject

from kube_downscaler.resources.constraint import KubeDownscalerJobsConstraint
from kube_downscaler.resources.constrainttemplate import ConstraintTemplate
from kube_downscaler.resources.keda import ScaledObject
from kube_downscaler.resources.policy import KubeDownscalerJobsPolicy
from kube_downscaler.resources.stack import Stack


def test_deployment():
    api_mock = MagicMock(spec=NamespacedAPIObject, name="APIMock")
    scalable_mock = {"spec": {"replicas": 3}}
    api_mock.obj = MagicMock(name="APIObjMock")
    d = Deployment(api_mock, scalable_mock)
    r = d.replicas
    assert r == 3

    d.replicas = 10
    assert scalable_mock["spec"]["replicas"] == 10


def test_statefulset():
    api_mock = MagicMock(spec=NamespacedAPIObject, name="APIMock")
    scalable_mock = {"spec": {"replicas": 3}}
    api_mock.obj = MagicMock(name="APIObjMock")
    d = StatefulSet(api_mock, scalable_mock)
    r = d.replicas
    assert r == 3
    d.replicas = 10
    assert scalable_mock["spec"]["replicas"] == 10


def test_stack():
    api_mock = MagicMock(spec=NamespacedAPIObject, name="APIMock")
    scalable_mock = {"spec": {"replicas": 3}}
    api_mock.obj = MagicMock(name="APIObjMock")
    d = Stack(api_mock, scalable_mock)
    r = d.replicas
    assert r == 3
    d.replicas = 10
    assert scalable_mock["spec"]["replicas"] == 10


def test_scaledobject():
    api_mock = MagicMock(spec=NamespacedAPIObject, name="APIMock")
    scalable_mock = {"metadata": {}}
    api_mock.obj = MagicMock(name="APIObjMock")
    d = ScaledObject(api_mock, scalable_mock)
    assert d.replicas == 1
    d.annotations[ScaledObject.keda_pause_annotation] = "0"
    assert d.replicas == 0

def test_kubedownscalerjobsconstraint():
    api_mock = MagicMock(spec=APIObject, name="APIMock")
    api_mock.obj = MagicMock(name="APIObjMock")
    d = KubeDownscalerJobsConstraint.create_job_constraint("constraint")
    assert d['metadata']['name'] == "constraint"
    assert d['spec']['match']['namespaces'][0] == "constraint"

def test_gatekeeper_crd():
    api_mock = MagicMock(spec=NamespacedAPIObject, name="APIMock")
    api_mock.obj = MagicMock(name="APIObjMock")
    d = ConstraintTemplate.create_constraint_template_crd(["kube-downscaler, downscaler"], matching_labels=frozenset([re.compile("")]))
    assert d['metadata']['name'] == "kubedownscalerjobsconstraint"
    assert "\"^(kube-downscaler, downscaler)$\"" in d['spec']['targets'][0]['rego']


def test_kubedownscalerjobspolicy():
    api_mock = MagicMock(spec=NamespacedAPIObject, name="APIMock")
    api_mock.obj = MagicMock(name="APIObjMock")
    d = KubeDownscalerJobsPolicy.create_job_policy("policy")
    assert d['metadata']['name'] == "kube-downscaler-jobs-policy"
    assert d['metadata']['namespace'] == "policy"