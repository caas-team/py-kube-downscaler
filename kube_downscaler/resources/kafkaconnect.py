from pykube.objects import NamespacedAPIObject


class KafkaConnect(NamespacedAPIObject):
    """Support the KafkaConnect resource (Strimzi, https://strimzi.io/docs/operators/latest/configuring.html#type-KafkaConnect-reference)."""

    version = "kafka.strimzi.io/v1beta2"
    endpoint = "kafkaconnects"
    kind = "KafkaConnect"

    @property
    def replicas(self):
        return self.obj["spec"].get("replicas")

    @replicas.setter
    def replicas(self, value):
        self.obj["spec"]["replicas"] = value
