from pykube.objects import NamespacedAPIObject


class ArgoRollout(NamespacedAPIObject):

    """Support the ArgoRollout resource (https://argoproj.github.io/argo-rollouts/features/specification/)."""

    version = "argoproj.io/v1alpha1"
    endpoint = "rollouts"
    kind = "Rollout"

    @property
    def replicas(self):
        replicas = self.obj["spec"].get("replicas")
        return replicas
