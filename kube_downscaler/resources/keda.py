from pykube.objects import NamespacedAPIObject


class ScaledObject(NamespacedAPIObject):

    """Support the ScaledObject resource (https://keda.sh/docs/2.7/concepts/scaling-deployments/#scaledobject-spec)."""

    version = "keda.sh/v1alpha1"
    endpoint = "scaledobjects"
    kind = "ScaledObject"

    keda_pause_annotation = "autoscaling.keda.sh/paused-replicas"
    last_keda_pause_annotation_if_present = "downscaler/original-pause-replicas"

    # If keda_pause_annotation is not present return -1 which means the ScaledObject is active
    # Otherwise returns the amount of replicas specified inside keda_pause_annotation
    @property
    def replicas(self):
        if ScaledObject.keda_pause_annotation in self.annotations:
            if self.annotations[ScaledObject.keda_pause_annotation] is None:
                replicas = -1
            elif self.annotations[ScaledObject.keda_pause_annotation] == "0":
                replicas = 0
            elif self.annotations[ScaledObject.keda_pause_annotation] != "0" and self.annotations[ScaledObject.keda_pause_annotation] is not None:
                replicas = int(self.annotations[ScaledObject.keda_pause_annotation])
        else:
            replicas = -1

        return replicas
