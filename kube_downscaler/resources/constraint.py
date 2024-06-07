from pykube.objects import APIObject


class KubeDownscalerJobsConstraint(APIObject):

    """Support the Gatakeeper Admission Controller Custom CRDs (https://open-policy-agent.github.io/gatekeeper/website/docs)."""

    version = "constraints.gatekeeper.sh/v1beta1"
    endpoint = "kubedownscalerjobsconstraint"
    kind = "KubeDownscalerJobsConstraint"

    @property
    def namespaces_list(self):
        return self.obj["spec"]["match"].get("namespaces", [])

    @namespaces_list.setter
    def namespaces_list(self, updated_list):
        self.obj["spec"]["match"]["namespaces"] = updated_list

    @staticmethod
    def create_job_constraint(resource_name):
        obj = {
            "apiVersion": "constraints.gatekeeper.sh/v1beta1",
            "kind": "KubeDownscalerJobsConstraint",
            "metadata": {
                "name": resource_name,
                "labels": {
                    "origin": "kube-downscaler"
                }
            },
            "spec": {
                "match": {
                    "namespaces": [resource_name]
                }
            }
        }

        return obj
