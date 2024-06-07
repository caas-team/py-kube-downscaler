from pykube.objects import APIObject

from kube_downscaler.helper import logger


class ConstraintTemplate(APIObject):

    """Support the Gatakeeper Admission Controller Custom CRDs (https://open-policy-agent.github.io/gatekeeper/website/docs)."""

    version = "templates.gatekeeper.sh/v1"
    endpoint = "constrainttemplates"
    kind = "ConstraintTemplate"

    @staticmethod
    def create_constraint_template_crd(excluded_jobs, matching_labels):

        excluded_jobs_regex = '^(' + '|'.join(excluded_jobs) + ')$'

        # For backwards compatibility, if the matching_labels FrozenSet has an empty string as the first element,
        # we don't ignore anything
        first_element = next(iter(matching_labels), None)
        first_element_str = first_element.pattern

        if first_element_str == "":
            logger.debug("Matching_labels arg set to empty string: all resources are considered in the scaling process")
            matching_labels_arg_is_present = False
        else:
            matching_labels_arg_is_present = True

        if matching_labels_arg_is_present:
            matching_labels_rego_string: str = "\n"
            for pattern in matching_labels:
                matching_labels_rego_string = matching_labels_rego_string + "    has_matched_labels(\"" + pattern.pattern + "\", input.review.object.metadata.labels)\n"
        else:
            matching_labels_rego_string: str = ""

        rego = """
        package kubedownscalerjobsconstraint

        violation[{"msg": msg}] {
            input.review.kind.kind == "Job"
            not exist_owner_reference
            not exact_match(\"""" + excluded_jobs_regex + """\", input.review.object.metadata.name)
            not has_exclude_annotation
            not is_exclude_until_date_reached""" + matching_labels_rego_string + """
            msg := "Job creation is not allowed in this namespace during a kube-downscaler downtime period."
        }

        exact_match(pattern, name) {
            regex.match(pattern, name)
        }

        exist_owner_reference {
	        input.review.object.metadata.ownerReferences
        }

        has_exclude_annotation {
            input.review.object.metadata.annotations["downscaler/exclude"] = "true"
        }

        is_exclude_until_date_reached {
            until_date_str := input.review.object.metadata.annotations["downscaler/exclude-until"]
            parsed_until_date := time.parse_rfc3339_ns(until_date_str)
            current_utc := time.now_ns()
            parsed_until_date >= current_utc
        }

        has_matched_labels(pattern, labels) {
            some k
            value := labels[k]
            key_equals_contact := concat("", [k, "="])
            equals_value_contact := concat("", [key_equals_contact, value])
            regex.match(pattern, equals_value_contact)
        }        
        """

        obj = {
            "apiVersion": "templates.gatekeeper.sh/v1",
            "kind": "ConstraintTemplate",
            "metadata": {
                "name": "kubedownscalerjobsconstraint",
                "annotations": {
                    "metadata.gatekeeper.sh/title": "Kube Downscaler Jobs Constraint",
                    "metadata.gatekeeper.sh/version": "1.0.0",
                    "description": "Policy to downscale jobs in certain namespaces."
                }
            },
            "spec": {
                "crd": {
                    "spec": {
                        "names": {
                            "kind": "KubeDownscalerJobsConstraint"
                        }
                    }
                },
                "targets": [
                    {
                        "target": "admission.k8s.gatekeeper.sh",
                        "rego": rego
                    }
                ]
            }
        }

        return obj
