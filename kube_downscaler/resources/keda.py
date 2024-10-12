from pykube.objects import NamespacedAPIObject


class ScaledObject(NamespacedAPIObject):

    """Support the ScaledObject resource (https://keda.sh/docs/2.7/concepts/scaling-deployments/#scaledobject-spec)."""

    version = "keda.sh/v1alpha1"
    endpoint = "scaledobjects"
    kind = "ScaledObject"

    keda_pause_annotation = "autoscaling.keda.sh/paused-replicas"
    last_keda_pause_annotation_if_present = "downscaler/original-pause-replicas"

    # GoLang 32-bit signed integer max value + 1. The value was choosen because 2147483647 is the max allowed
    # for Deployment/StatefulSet.spec.template.replicas
    KUBERNETES_MAX_ALLOWED_REPLICAS = 2147483647

    @property
    def replicas(self):
        if ScaledObject.keda_pause_annotation in self.annotations:
            if self.annotations[ScaledObject.keda_pause_annotation] is None:
                replicas = self.KUBERNETES_MAX_ALLOWED_REPLICAS + 1
            elif self.annotations[ScaledObject.keda_pause_annotation] == "0":
                replicas = 0
            elif self.annotations[ScaledObject.keda_pause_annotation] != "0" and self.annotations[ScaledObject.keda_pause_annotation] is not None:
                replicas = int(self.annotations[ScaledObject.keda_pause_annotation])
        else:
            replicas = self.KUBERNETES_MAX_ALLOWED_REPLICAS + 1

        return replicas
