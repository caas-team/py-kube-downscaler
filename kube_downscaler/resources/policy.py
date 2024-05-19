from pykube.objects import NamespacedAPIObject


class KubeDownscalerJobsPolicy(NamespacedAPIObject):

    """Support the Kyverno Admission Controller Custom CRDs (https://kyverno.io/docs/introduction/#quick-start)."""

    version = "kyverno.io/v1"
    endpoint = "policies"
    kind = "Policy"

    @staticmethod
    def create_job_policy(namespace):
        obj = {
            "apiVersion": "kyverno.io/v1",
            "kind": "Policy",
            "metadata": {
                "name": "kube-downscaler-jobs-policy",
                "namespace": namespace,
                "labels": {
                    "origin": "kube-downscaler",
                    "kube-downscaler/policy-type": "without-matching-labels"
                },
                "annotations": {
                    "policies.kyverno.io/title": "Kube Downscaler Jobs Policy",
                    "policies.kyverno.io/severity": "medium",
                    "policies.kyverno.io/subject": "Job",
                    "policies.kyverno.io/description": "Job creation is not allowed in this namespace during a kube-downscaler downtime period."
                }
            },
            "spec": {
                "validationFailureAction": "Enforce",
                "rules": [
                    {
                        "name": "kube-downscaler-jobs-policy",
                        "match": {
                            "any": [
                                {
                                    "resources": {
                                        "kinds": ["Job"]
                                    }
                                }
                            ]
                        },
                        "validate": {
                            "message": "Job creation is not allowed in this namespace during a kube-downscaler downtime period.",
                            "deny": {
                                "conditions": {
                                    "all": [
                                        {
                                            "key": "{{ request.object.metadata.ownerReferences || 'null'}}",
                                            "operator": "Equals",
                                            "value": "null"
                                        },
                                        {
                                            "key": "{{request.object.metadata.annotations.\"downscaler/exclude\" || ''}}",
                                            "operator": "NotEquals",
                                            "value": "true"
                                        },
                                        {
                                            "key": "{{ time_after('{{ time_now() }}','{{ request.object.metadata.annotations.\"downscaler/exclude-until\" || '1970-01-01T00:00:00Z' }}') }}",
                                            "operator": "Equals",
                                            "value": True
                                        }
                                    ]
                                }
                            }
                        }
                    }
                ]
            }
        }

        return obj

    @staticmethod
    def create_job_policy_with_matching_labels(namespace, matching_labels):
        obj = {
            "apiVersion": "kyverno.io/v1",
            "kind": "Policy",
            "metadata": {
                "name": "kube-downscaler-jobs-policy",
                "namespace": namespace,
                "labels": {
                    "origin": "kube-downscaler",
                    "kube-downscaler/policy-type": "with-matching-labels"
                },
                "annotations": {
                    "policies.kyverno.io/description": "Job creation is not allowed in this namespace during a kube-downscaler downtime period.",
                    "policies.kyverno.io/severity": "medium",
                    "policies.kyverno.io/subject": "Job",
                    "policies.kyverno.io/title": "Kube Downscaler Jobs Policy"
                }
            },
            "spec": {
                "validationFailureAction": "Enforce",
                "rules": [
                    {
                        "match": {
                            "any": [
                                {
                                    "resources": {
                                        "kinds": ["Job"]
                                    }
                                }
                            ]
                        },
                        "name": "kube-downscaler-jobs-policy",
                        "preconditions": {
                            "all": [
                                {
                                    "key": "{{ request.object.metadata.labels || 'NoLabel'}}",
                                    "operator": "NotEquals",
                                    "value": "NoLabel"
                                }
                            ]
                        },
                        "context": [
                            {
                                "name": "labels",
                                "variable": {
                                    "jmesPath": "items(request.object.metadata.labels, 'key', 'value')",
                                    "default": []
                                }
                            }
                        ],
                        "validate": {
                            "message": "Job creation is not allowed in this namespace during a kube-downscaler downtime period.",
                            "foreach": [
                                {
                                    "list": "labels",
                                    "deny": {
                                        "conditions": {
                                            "all": [
                                                {
                                                    "key": "{{ request.object.metadata.ownerReferences || 'null'}}",
                                                    "operator": "Equals",
                                                    "value": "null"
                                                },
                                                {
                                                    "key": "{{request.object.metadata.annotations.\"downscaler/exclude\" || ''}}",
                                                    "operator": "NotEquals",
                                                    "value": "true"
                                                },
                                                {
                                                    "key": "{{ time_after('{{ time_now() }}','{{ request.object.metadata.annotations.\"downscaler/exclude-until\" || '1970-01-01T00:00:00Z' }}') }}",
                                                    "operator": "Equals",
                                                    "value": True
                                                }
                                            ]
                                        }
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        }

        for pattern in matching_labels:
            matching_labels_condition = {
                "key": "{{ regex_match('" + pattern.pattern + "', '{{element.key}}={{element.value}}') }}",
                "operator": "Equals",
                "value": True
            }
            obj["spec"]["rules"][0]["validate"]["foreach"][0]["deny"]["conditions"]["all"].append(
                matching_labels_condition)

        return obj

    @staticmethod
    def append_excluded_jobs_condition(obj, excluded_jobs, has_matching_labels_arg):

        excluded_jobs_regex = f"^({'|'.join(excluded_jobs)})$"

        excluded_jobs_condition = {
            "key": "{{ regex_match('" + excluded_jobs_regex + "', '{{request.object.metadata.name}}') }}",
            "operator": "NotEquals",
            "value": True
        }

        if has_matching_labels_arg:
            obj["spec"]["rules"][0]["validate"]["foreach"][0]["deny"]["conditions"]["all"].append(
                excluded_jobs_condition)
        else:
            obj["spec"]["rules"][0]["validate"]["deny"]["conditions"]["all"].append(excluded_jobs_condition)

        return obj

    @property
    def type(self):
        return self.obj["metadata"]["labels"]["kube-downscaler/policy-type"]
