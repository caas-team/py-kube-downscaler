from pykube.objects import NamespacedAPIObject


class AutoscalingRunnerSet(NamespacedAPIObject):
    """Support the AutoscalingRunnerSet resource (https://github.com/actions/actions-runner-controller)."""

    version = "actions.github.com/v1alpha1"
    endpoint = "autoscalingrunnersets"
    kind = "AutoscalingRunnerSet"

    @property
    def replicas(self):
        return self.obj["spec"].get("minRunners")

    @replicas.setter
    def replicas(self, value):
        self.obj["spec"]["minRunners"] = value
