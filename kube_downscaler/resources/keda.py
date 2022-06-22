from pykube.objects import NamespacedAPIObject


class ScaledObject(NamespacedAPIObject):

    """Support the ScaledObject resource (https://keda.sh/docs/2.7/concepts/scaling-deployments/#scaledobject-spec)."""

    version = "keda.sh/v1alpha1"
    endpoint = "scaledobjects"
    kind = "ScaledObject"

    keda_pause_annotation = "autoscaling.keda.sh/paused-replicas"

    @property
    def replicas(self):
        replicas = 0 if ScaledObject.keda_pause_annotation in self.annotations else 1
        return replicas
