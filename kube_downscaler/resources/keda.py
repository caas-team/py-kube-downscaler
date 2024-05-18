from pykube.objects import NamespacedAPIObject


class ScaledObject(NamespacedAPIObject):

    """Support the ScaledObject resource (https://keda.sh/docs/2.7/concepts/scaling-deployments/#scaledobject-spec)."""

    version = "keda.sh/v1alpha1"
    endpoint = "scaledobjects"
    kind = "ScaledObject"

    keda_pause_annotation = "autoscaling.keda.sh/paused-replicas"
    last_keda_pause_annotation_if_present = "downscaler/original-pause-replicas"

    @property
    def replicas(self):
        if ScaledObject.keda_pause_annotation in self.annotations:
            if self.annotations[ScaledObject.keda_pause_annotation] == "0":
                replicas = 0
            elif self.annotations[ScaledObject.keda_pause_annotation] != "0":
                replicas = int(self.annotations[ScaledObject.keda_pause_annotation])
        else:
            replicas = 1

        return replicas
