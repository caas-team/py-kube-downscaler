import collections
import datetime
import logging
import re
import time
from typing import Any
from typing import FrozenSet
from typing import List
from typing import Optional
from typing import Pattern
from typing import Tuple

import pykube
import requests
from pykube import CronJob
from pykube import CustomResourceDefinition
from pykube import DaemonSet
from pykube import Deployment
from pykube import HorizontalPodAutoscaler
from pykube import HTTPClient
from pykube import Job
from pykube import Namespace
from pykube import StatefulSet
from pykube.exceptions import HTTPError
from pykube.objects import APIObject
from pykube.objects import NamespacedAPIObject
from pykube.objects import PodDisruptionBudget

from kube_downscaler import helper
from kube_downscaler.helper import matches_time_spec
from kube_downscaler.resources.autoscalingrunnerset import AutoscalingRunnerSet
from kube_downscaler.resources.constraint import KubeDownscalerJobsConstraint
from kube_downscaler.resources.constrainttemplate import ConstraintTemplate
from kube_downscaler.resources.keda import ScaledObject
from kube_downscaler.resources.policy import KubeDownscalerJobsPolicy
from kube_downscaler.resources.rollout import ArgoRollout
from kube_downscaler.resources.stack import Stack

ORIGINAL_REPLICAS_ANNOTATION = "downscaler/original-replicas"
FORCE_UPTIME_ANNOTATION = "downscaler/force-uptime"
FORCE_DOWNTIME_ANNOTATION = "downscaler/force-downtime"
UPSCALE_PERIOD_ANNOTATION = "downscaler/upscale-period"
DOWNSCALE_PERIOD_ANNOTATION = "downscaler/downscale-period"
EXCLUDE_ANNOTATION = "downscaler/exclude"
EXCLUDE_UNTIL_ANNOTATION = "downscaler/exclude-until"
UPTIME_ANNOTATION = "downscaler/uptime"
DOWNTIME_ANNOTATION = "downscaler/downtime"
DOWNTIME_REPLICAS_ANNOTATION = "downscaler/downtime-replicas"
GRACE_PERIOD_ANNOTATION = "downscaler/grace-period"

# GoLang 32-bit signed integer max value + 1. The value was choosen because 2147483647 is the max allowed
# for Deployment/StatefulSet.spec.template.replicas. This value is used to allow
# ScaledObject to support "downscaler/downtime-replcas" annotation
KUBERNETES_MAX_ALLOWED_REPLICAS = 2147483647

RESOURCE_CLASSES = [
    Deployment,
    StatefulSet,
    Stack,
    CronJob,
    HorizontalPodAutoscaler,
    ArgoRollout,
    ScaledObject,
    DaemonSet,
    PodDisruptionBudget,
    Job,
    AutoscalingRunnerSet,
]

TIMESTAMP_FORMATS = [
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d",
]

ADMISSION_CONTROLLERS = ["gatekeeper", "kyverno"]

logger = logging.getLogger(__name__)


def parse_time(timestamp: str) -> datetime.datetime:
    for fmt in TIMESTAMP_FORMATS:
        try:
            dt = datetime.datetime.strptime(timestamp, fmt)
        except ValueError:
            pass
        else:
            return dt.replace(tzinfo=datetime.timezone.utc)
    raise ValueError(
        f"time data '{timestamp}' does not match any format ({', '.join(TIMESTAMP_FORMATS)})"
    )


# If the argument --upscale-target-only is present, resources from namespaces not in target won't be processed.
# Otherwise all resources from all namespaces will be processed for scaling if the have original_replicas annotation
def define_scope(exclude, original_replicas, upscale_target_only):
    if upscale_target_only:
        exclude_condition = exclude
    else:
        exclude_condition = exclude and not original_replicas

    return exclude_condition


def is_grace_period_annotation_integer(value):
    try:
        int(value)  # Attempt to convert the string to an integer
        return True
    except ValueError:
        return False


def within_grace_period(
    resource,
    grace_period: int,
    now: datetime.datetime,
    deployment_time_annotation: Optional[str] = None,
):
    update_time = parse_time(resource.metadata["creationTimestamp"])

    grace_period_annotation = resource.annotations.get(GRACE_PERIOD_ANNOTATION, None)

    if grace_period_annotation is not None and is_grace_period_annotation_integer(
        grace_period_annotation
    ):
        grace_period_annotation_integer = int(grace_period_annotation)

        if grace_period_annotation_integer > 0:
            if grace_period_annotation_integer <= grace_period:
                logger.debug(
                    f"Grace period annotation found for {resource.kind} {resource.name} in namespace {resource.namespace}. "
                    f"Since the grace period specified in the annotation is shorter than the global grace period, "
                    f"the downscaler will use the annotation's grace period for this resource."
                )
                grace_period = grace_period_annotation_integer
            else:
                logger.debug(
                    f"Grace period annotation found for {resource.kind} {resource.name} in namespace {resource.namespace}. "
                    f"The global grace period is shorter, so the downscaler will use the global grace period for this resource."
                )
        else:
            logger.debug(
                f"Grace period annotation found for {resource.kind} {resource.name} in namespace {resource.namespace} "
                f"but cannot be a negative integer"
            )

    if deployment_time_annotation:
        annotations = resource.metadata.get("annotations", {})
        deployment_time = annotations.get(deployment_time_annotation)
        if deployment_time:
            try:
                update_time = max(update_time, parse_time(deployment_time))
            except ValueError as e:
                logger.warning(
                    f"Invalid {deployment_time_annotation} in {resource.namespace}/{resource.name}: {e}"
                )
    delta = now - update_time
    return delta.total_seconds() <= grace_period


def within_grace_period_namespace(
    resource: APIObject,
    grace_period: int,
    now: datetime.datetime,
    deployment_time_annotation: Optional[str] = None,
):
    update_time = parse_time(resource.metadata["creationTimestamp"])

    grace_period_annotation = resource.annotations.get(GRACE_PERIOD_ANNOTATION, None)

    if grace_period_annotation is not None and is_grace_period_annotation_integer(
        grace_period_annotation
    ):
        grace_period_annotation_integer = int(grace_period_annotation)

        if grace_period_annotation_integer > 0:
            if grace_period_annotation_integer <= grace_period:
                logger.debug(
                    f"Grace period annotation found for namespace {resource.name}. "
                    f"Since the grace period specified in the annotation is shorter than the global grace period, "
                    f"the downscaler will use the annotation's grace period for this resource."
                )
                grace_period = grace_period_annotation_integer
            else:
                logger.debug(
                    f"Grace period annotation found for namespace {resource.name}. "
                    f"The global grace period is shorter, so the downscaler will use the global grace period for this resource."
                )
        else:
            logger.debug(
                f"Grace period annotation found for namespace {resource.name} "
                f"but cannot be a negative integer"
            )

    if deployment_time_annotation:
        annotations = resource.metadata.get("annotations", {})
        deployment_time = annotations.get(deployment_time_annotation)
        if deployment_time:
            try:
                update_time = max(update_time, parse_time(deployment_time))
            except ValueError as e:
                logger.warning(
                    f"Invalid {deployment_time_annotation} in {resource.kind}/{resource.name}: {e}"
                )
    delta = now - update_time
    return delta.total_seconds() <= grace_period


def pods_force_uptime(api, namespace: FrozenSet[str]):
    """Return True if there are any running pods which require the deployments to be scaled back up."""
    pods = get_pod_resources(api, namespace)

    for pod in pods:
        if pod.obj.get("status", {}).get("phase") in ("Succeeded", "Failed"):
            continue
        if pod.annotations.get(FORCE_UPTIME_ANNOTATION, "").lower() == "true":
            logger.info(f"Forced uptime because of {pod.namespace}/{pod.name}")
            return True
    return False


def get_pod_resources(api, namespaces: FrozenSet[str]):
    if len(namespaces) >= 1:
        pods = []
        for namespace in namespaces:
            try:
                pods_query_result = helper.call_with_exponential_backoff(
                    lambda: pykube.Pod.objects(api).filter(namespace=namespace),
                    context_msg=f"fetching pods for namespace {namespace}",
                )
                pods += pods_query_result
            except requests.HTTPError as e:
                if e.response.status_code == 404:
                    logger.debug(f"No pods found in namespace {namespace} (404)")
                elif e.response.status_code == 429:
                    logger.warning(
                        "KubeDownscaler is being rate-limited by the Kubernetes API while querying namespaces (429 Too Many Requests). Retrying at next cycle"
                    )
                elif e.response.status_code == 403:
                    logger.warning(
                        f"Not authorized to access the Namespace {namespace} (403). Please check your RBAC settings if you are using constrained mode. "
                        f"Ensure that a Role with proper access to the necessary resources and a RoleBinding have been deployed to this Namespace."
                        f"The RoleBinding should be linked to the KubeDownscaler Service Account."
                    )
                else:
                    raise e
    else:
        try:
            pods = helper.call_with_exponential_backoff(
                lambda: pykube.Pod.objects(api).filter(namespace=pykube.all),
                context_msg="fetching pods clusterwide",
            )
        except requests.HTTPError as e:
            if e.response.status_code == 403:
                logger.warning(
                    "KubeDownscaler is not authorized to perform a cluster wide query to retrieve Pods (403)"
                )
            elif e.response.status_code == 429:
                logger.warning(
                    "KubeDownscaler is being rate-limited by the Kubernetes API while querying namespaces (429 Too Many Requests). Retrying at next cycle"
                )
            else:
                raise e

    return pods


def create_excluded_namespaces_regex(namespaces: FrozenSet[str]):
    # Ensure the input is a FrozenSet of strings
    if not isinstance(namespaces, FrozenSet):
        raise TypeError("namespaces must be of type FrozenSet[str]")
    if not all(isinstance(ns, str) for ns in namespaces):
        raise TypeError("All elements of namespaces must be strings")

    # Escape special regex characters in each namespace name
    escaped_namespaces = [re.escape(ns) for ns in namespaces]

    # Combine the escaped names into a single alternation pattern
    combined_pattern = "|".join(escaped_namespaces)

    # Create a regex pattern that matches any string not exactly one of the namespaces
    excluded_pattern = f"^(?!{combined_pattern}$).+"

    logger.info(
        "--namespace arg is not empty the --exclude-namespaces argument was modified to the following regex pattern: "
        + excluded_pattern
    )

    # Compile and return the regex pattern
    return [re.compile(excluded_pattern)]


def get_namespace_to_namespace_obj(api, namespaces):
    namespace_to_namespace_objects = {}
    if len(namespaces) >= 1:
        try:
            namespace_objects = helper.call_with_exponential_backoff(
                lambda: Namespace.objects(api).filter(
                    selector={"kubernetes.io/metadata.name__in": namespaces}
                ),
                context_msg=f"fetching namespaces {namespaces}",
            )
            for obj in namespace_objects:
                namespace_to_namespace_objects[obj.name] = obj
        except requests.HTTPError as e:
            if e.response.status_code == 403:
                logger.error(
                    "KubeDownscaler is not authorized to query namespaces (403). Please check your RBAC settings if you are using constrained mode. "
                    "Ensure that a Role with proper access to the necessary resources and a RoleBinding have been deployed to this Namespace."
                    "The RoleBinding should be linked to the KubeDownscaler Service Account."
                )
            if e.response.status_code == 429:
                logger.warning(
                    "KubeDownscaler is being rate-limited by the Kubernetes API while querying namespaces (429 Too Many Requests). Retrying at next cycle "
                )
            else:
                raise e
    else:
        try:
            namespace_objects = helper.call_with_exponential_backoff(
                lambda: Namespace.objects(api), context_msg="fetching all namespaces"
            )
            for obj in namespace_objects:
                namespace_to_namespace_objects[obj.name] = obj
        except requests.HTTPError as e:
            if e.response.status_code == 403:
                logger.error(
                    "KubeDownscaler is not authorized to query namespaces (403). Please check your RBAC settings if you are using constrained mode. "
                    "Ensure that a Role with proper access to the necessary resources and a RoleBinding have been deployed to this Namespace."
                    "The RoleBinding should be linked to the KubeDownscaler Service Account."
                )
            if e.response.status_code == 429:
                logger.warning(
                    "KubeDownscaler is being rate-limited by the Kubernetes API while querying namespaces (429 Too Many Requests). Retrying at next cycle"
                )
            else:
                raise e

    return namespace_to_namespace_objects


def get_resources(kind, api, namespaces: FrozenSet[str], excluded_namespaces):
    if len(namespaces) >= 1:
        resources = []
        excluded_namespaces = create_excluded_namespaces_regex(namespaces)
        for namespace in namespaces:
            try:
                resources_inside_namespace = helper.call_with_exponential_backoff(
                    lambda: kind.objects(api, namespace=namespace),
                    context_msg=f"{kind.endpoint} in namespace {namespace}",
                )
                resources += resources_inside_namespace
            except requests.HTTPError as e:
                if e.response.status_code == 404:
                    logger.debug(
                        f"No {kind.endpoint} found in namespace {namespace} (404)"
                    )
                if e.response.status_code == 403:
                    logger.error(
                        f"KubeDownscaler is not authorized to access the Namespace {namespace} (403). Please check your RBAC settings if you are using constrained mode. "
                        f"Ensure that a Role with proper access to the necessary resources and a RoleBinding have been deployed to this Namespace."
                        f"The RoleBinding should be linked to the KubeDownscaler Service Account."
                    )
                if e.response.status_code == 429:
                    logger.warning(
                        f"KubeDownscaler is being rate-limited by the Kubernetes API while querying {kind.endpoint} (429 Too Many Requests). Retrying at next cycle "
                    )
                else:
                    raise e
    else:
        try:
            resources = helper.call_with_exponential_backoff(
                lambda: kind.objects(api, namespace=pykube.all),
                context_msg=f"retrieving {kind.endpoint}s cluster-wide",
            )
        except requests.HTTPError as e:
            if e.response.status_code == 403:
                logger.warning(
                    f"KubeDownscaler is not authorized to perform a cluster wide query to retrieve {kind.endpoint} (403)"
                )
            if e.response.status_code == 429:
                logger.warning(
                    f"KubeDownscaler is being rate-limited by the Kubernetes API while querying {kind.endpoint} (429 Too Many Requests). Retrying at next cycle"
                )
            else:
                raise e

    return resources, excluded_namespaces


def get_resource(kind, api, namespace, resource_name: str):
    try:
        resource = helper.call_with_exponential_backoff(
            lambda: kind.objects(api)
            .filter(namespace=namespace)
            .get_or_none(name=resource_name),
            context_msg=f"retrieving {kind.endpoint} in namespace {namespace}",
        )
        if resource is None:
            logger.debug(f"{kind.endpoint} {namespace}/{resource_name} not found")
    except requests.HTTPError as e:
        resource = None
        if e.response.status_code == 404:
            logger.debug(
                f"{kind} {resource_name} not found in namespace {namespace} (404)"
            )
        if e.response.status_code == 403:
            logger.warning(
                f"KubeDownscaler is not authorized to to retrieve {kind} {namespace}/{resource_name} (403)"
            )
        if e.response.status_code == 429:
            logger.warning(
                f"KubeDownscaler is being rate-limited by the Kubernetes API while querying {kind.endpoint} (429 Too Many Requests). Retrying at next cycle"
            )
        else:
            raise e

    return resource


def scale_jobs_without_admission_controller(
    plural, admission_controller, constrainted_downscaler
):
    return (plural == "jobs" and admission_controller == "") or constrainted_downscaler


def is_stack_deployment(resource: NamespacedAPIObject) -> bool:
    if resource.kind == Deployment.kind and resource.version == Deployment.version:
        for owner_ref in resource.metadata.get("ownerReferences", []):
            if (
                owner_ref["apiVersion"] == Stack.version
                and owner_ref["kind"] == Stack.kind
            ):
                return True
    return False


def ignore_if_labels_dont_match(
    resource: NamespacedAPIObject, labels: FrozenSet[Pattern]
) -> bool:
    # For backwards compatibility, if there is no label filter, we don't ignore anything
    if not any(label.pattern for label in labels):
        return False

    # Ignore resources whose labels do not match the set of input labels
    resource_labels = [f"{key}={value}" for key, value in resource.labels.items()]
    ignore = True
    for label_pattern in labels:
        if not ignore:
            break
        ignore = not any(
            [
                label_pattern.fullmatch(resource_label)
                for resource_label in resource_labels
            ]
        )
    return ignore


def ignore_resource(resource: NamespacedAPIObject, now: datetime.datetime) -> bool:
    # Ignore deployments managed by stacks, we will downscale the stack instead
    if is_stack_deployment(resource):
        return True

    # any value different from "false" will ignore the resource (to be on the safe side)
    if resource.annotations.get(EXCLUDE_ANNOTATION, "false").lower() != "false":
        return True

    exclude_until = resource.annotations.get(EXCLUDE_UNTIL_ANNOTATION)
    if exclude_until:
        try:
            until_ts = parse_time(exclude_until)
        except ValueError as e:
            logger.warning(
                f"Invalid annotation value for '{EXCLUDE_UNTIL_ANNOTATION}' on {resource.namespace}/{resource.name}: {e}"
            )
            # we will ignore the invalid timestamp and treat the resource as not excluded
            return False
        if now < until_ts:
            return True

    return False


def get_replicas(
    resource: NamespacedAPIObject, original_replicas: Optional[int], uptime: str
):
    replicas_is_percentage = False

    if resource.kind in ["CronJob", "Job"]:
        suspended = resource.obj["spec"]["suspend"]
        replicas = 0 if suspended else 1
        state = "suspended" if suspended else "not suspended"
        original_state = "suspended" if original_replicas == 0 else "not suspended"
        logger.debug(
            f"{resource.kind} {resource.namespace}/{resource.name} is {state} (original: {original_state}, uptime: {uptime})"
        )
    elif resource.kind == "PodDisruptionBudget":
        if "minAvailable" in resource.obj["spec"]:
            replicas = resource.obj["spec"]["minAvailable"]
            if "%" in str(replicas):
                replicas = int(str(replicas).replace("%", ""))
                replicas_is_percentage = True
            logger.debug(
                f"{resource.kind} {resource.namespace}/{resource.name} has {replicas} minAvailable (original: {original_replicas}, uptime: {uptime})"
            )
        elif "maxUnavailable" in resource.obj["spec"]:
            replicas = resource.obj["spec"]["maxUnavailable"]
            if "%" in str(replicas):
                replicas = int(str(replicas).replace("%", ""))
                replicas_is_percentage = True
            logger.debug(
                f"{resource.kind} {resource.namespace}/{resource.name} has {replicas} maxUnavailable (original: {original_replicas}, uptime: {uptime})"
            )
        else:
            replicas = 0
            logger.debug(
                f"{resource.kind} {resource.namespace}/{resource.name} has neither minAvailable nor maxUnavailable (original: {original_replicas}, uptime: {uptime})"
            )
    elif resource.kind == "HorizontalPodAutoscaler":
        replicas = resource.obj["spec"]["minReplicas"]
        logger.debug(
            f"{resource.kind} {resource.namespace}/{resource.name} has {replicas} minReplicas (original: {original_replicas}, uptime: {uptime})"
        )
    elif resource.kind == "DaemonSet":
        if "nodeSelector" in resource.obj["spec"]["template"]["spec"]:
            kube_downscaler_node_selector_dict = resource.obj["spec"]["template"][
                "spec"
            ]["nodeSelector"]
        else:
            kube_downscaler_node_selector_dict = None
        if kube_downscaler_node_selector_dict is None:
            suspended = False
        else:
            if "kube-downscaler-non-existent" in kube_downscaler_node_selector_dict:
                suspended = True
            else:
                suspended = False
        replicas = 0 if suspended else 1
        state = "suspended" if suspended else "not suspended"
        original_state = "suspended" if original_replicas == 0 else "not suspended"
        logger.debug(
            f"{resource.kind} {resource.namespace}/{resource.name} is {state} (original: {original_state}, uptime: {uptime})"
        )
    elif resource.kind == "ScaledObject":
        replicas = resource.replicas
        if replicas == KUBERNETES_MAX_ALLOWED_REPLICAS + 1:
            logger.debug(
                f"{resource.kind} {resource.namespace}/{resource.name} is not suspended (uptime: {uptime})"
            )
        else:
            logger.debug(
                f"{resource.kind} {resource.namespace}/{resource.name} is suspended (uptime: {uptime})"
            )
    else:
        replicas = resource.replicas
        logger.debug(
            f"{resource.kind} {resource.namespace}/{resource.name} has {replicas} replicas (original: {original_replicas}, uptime: {uptime})"
        )
    return replicas, replicas_is_percentage


def scale_up_jobs(
    api,
    resource: NamespacedAPIObject,
    uptime,
    downtime,
    admission_controller: str,
    dry_run: bool,
    enable_events: bool,
) -> APIObject:
    policy: APIObject = None
    operation = "no_scale"

    event_message = "Scaling up jobs"
    if admission_controller == "gatekeeper":
        policy = KubeDownscalerJobsConstraint.objects(api).get_or_none(
            name=resource.name
        )
        if policy is not None:
            operation = "scale_up"
            logger.info(
                f"Unsuspending jobs for {resource.kind}/{resource.name} (uptime: {uptime}, downtime: {downtime})"
            )
        else:
            operation = "no_scale"
    if admission_controller == "kyverno":
        policy_name = "kube-downscaler-jobs-policy"
        policy = (
            KubeDownscalerJobsPolicy.objects(api)
            .filter(namespace=resource.name)
            .get_or_none(name=policy_name)
        )
        if policy is not None:
            operation = "scale_up"
            logger.info(
                f"Unsuspending jobs for {resource.kind}/{resource.name} (uptime: {uptime}, downtime: {downtime})"
            )
        else:
            operation = "no_scale"
    if enable_events:
        helper.add_event(
            resource,
            event_message,
            "ScaleUp",
            "Normal",
            dry_run,
        )
    return policy, operation


def scale_down_jobs(
    api,
    resource: NamespacedAPIObject,
    uptime,
    downtime,
    admission_controller: str,
    excluded_jobs: List[str],
    matching_labels: FrozenSet[Pattern],
    dry_run: bool,
    enable_events: bool,
) -> Tuple[Optional[Any], str]:
    policy: APIObject = None
    operation = "no_scale"
    obj = None

    event_message = "Scaling down jobs"
    if admission_controller == "gatekeeper":
        policy = KubeDownscalerJobsConstraint.objects(api).get_or_none(
            name=resource.name
        )
        if policy is None:
            obj = KubeDownscalerJobsConstraint.create_job_constraint(resource.name)
            operation = "scale_down"
            logger.info(
                f"Suspending jobs for {resource.kind}/{resource.name} (uptime: {uptime}, downtime: {downtime})"
            )
        else:
            obj = policy
            operation = "no_scale"
    if admission_controller == "kyverno":
        # if the matching_labels FrozenSet has an empty string as the first element, we create a different kyverno policy
        first_element = next(iter(matching_labels), "")

        if first_element == "":
            has_matching_labels_arg = False
        else:
            has_matching_labels_arg = True

        policy_name = "kube-downscaler-jobs-policy"
        policy = (
            KubeDownscalerJobsPolicy.objects(api)
            .filter(namespace=resource.name)
            .get_or_none(name=policy_name)
        )

        if policy is None:
            if has_matching_labels_arg:
                obj = KubeDownscalerJobsPolicy.create_job_policy_with_matching_labels(
                    resource.name, matching_labels
                )
            else:
                obj = KubeDownscalerJobsPolicy.create_job_policy(resource.name)

            if len(excluded_jobs) > 0:
                obj = KubeDownscalerJobsPolicy.append_excluded_jobs_condition(
                    obj, excluded_jobs, has_matching_labels_arg
                )
            operation = "scale_down"
            logger.info(
                f"Suspending jobs for {resource.kind}/{resource.name} (uptime: {uptime}, downtime: {downtime})"
            )
        else:
            if has_matching_labels_arg and policy.type == "with-matching-labels":
                obj = policy
                operation = "no_scale"
                logger.debug(
                    "No need to update kyverno policy, correctly found a policy with matching label"
                )
            elif has_matching_labels_arg and policy.type != "with-matching-labels":
                operation = "kyverno_update"
                obj = KubeDownscalerJobsPolicy.create_job_policy_with_matching_labels(
                    resource.name, matching_labels
                )
                if len(excluded_jobs) > 0:
                    obj = KubeDownscalerJobsPolicy.append_excluded_jobs_condition(
                        obj, excluded_jobs, has_matching_labels_arg
                    )
                logger.debug(
                    "Update needed for kyverno policy, found a policy without matching label but need a policy with matching label"
                )
            elif (
                not has_matching_labels_arg and policy.type == "without-matching-labels"
            ):
                obj = policy
                operation = "no_scale"
                logger.debug(
                    "No need to update kyverno policy, correctly found a policy without matching label"
                )
            elif (
                not has_matching_labels_arg and policy.type != "without-matching-labels"
            ):
                operation = "kyverno_update"
                obj = KubeDownscalerJobsPolicy.create_job_policy(resource.name)
                if len(excluded_jobs) > 0:
                    obj = KubeDownscalerJobsPolicy.append_excluded_jobs_condition(
                        obj, excluded_jobs, has_matching_labels_arg
                    )
                logger.debug(
                    "Update needed for kyverno policy, found a policy with matching label but need a policy without matching label"
                )
            else:
                obj = policy
                operation = "no_scale"
                logger.debug("No Update Needed For Policy, all conditions were not met")
    if enable_events:
        helper.add_event(
            resource,
            event_message,
            "ScaleDown",
            "Normal",
            dry_run,
        )
    return obj, operation


def scale_up(
    resource: NamespacedAPIObject,
    replicas: int,
    replicas_is_percentage,
    original_replicas: int,
    is_original_replicas_percentage,
    uptime,
    downtime,
    dry_run: bool,
    enable_events: bool,
):
    event_message = "Scaling up replicas"
    if is_original_replicas_percentage and resource.kind != "PodDisruptionBudget":
        logger.warning(
            f"Skipping scale up for {resource.kind} {resource.namespace}/{resource.name}: "
            f"percentage values for 'downscaler/original-replicas' are supported only on PodDisruptionBudget objects, "
            f"the user is not supposed to manually add or modify this annotation on resources, please restore it to the original state"
            f"(uptime: {uptime}, downtime: {downtime})"
        )
        raise ValueError(
            f"percentage 'original-replicas' are not supported for {resource.kind}"
        )

    if resource.kind == "DaemonSet":
        resource.obj["spec"]["template"]["spec"]["nodeSelector"][
            "kube-downscaler-non-existent"
        ] = None
        logger.info(
            f"Unsuspending {resource.kind} {resource.namespace}/{resource.name} (uptime: {uptime}, downtime: {downtime})"
        )
        event_message = "Unsuspending DaemonSet"
    elif resource.kind in ["CronJob", "Job"]:
        resource.obj["spec"]["suspend"] = False
        logger.info(
            f"Unsuspending {resource.kind} {resource.namespace}/{resource.name} (uptime: {uptime}, downtime: {downtime})"
        )
        event_message = f"Unsuspending {resource.kind}"
    elif resource.kind == "PodDisruptionBudget":
        if "minAvailable" in resource.obj["spec"]:
            target = (
                f"{original_replicas}%"
                if is_original_replicas_percentage
                else original_replicas
            )
            starting_replicas = f"{replicas}%" if replicas_is_percentage else replicas
            resource.obj["spec"]["minAvailable"] = target
            logger.info(
                f"Scaling up {resource.kind} {resource.namespace}/{resource.name} from {starting_replicas} to {target} minAvailable (uptime: {uptime}, downtime: {downtime})"
            )
        elif "maxUnavailable" in resource.obj["spec"]:
            target = (
                f"{original_replicas}%"
                if is_original_replicas_percentage
                else original_replicas
            )
            starting_replicas = f"{replicas}%" if replicas_is_percentage else replicas
            resource.obj["spec"]["maxUnavailable"] = target
            logger.info(
                f"Scaling up {resource.kind} {resource.namespace}/{resource.name} from {starting_replicas} to {target} maxUnavailable (uptime: {uptime}, downtime: {downtime})"
            )
    elif resource.kind == "HorizontalPodAutoscaler":
        resource.obj["spec"]["minReplicas"] = original_replicas
        logger.info(
            f"Scaling up {resource.kind} {resource.namespace}/{resource.name} from {replicas} to {original_replicas} minReplicas (uptime: {uptime}, downtime: {downtime})"
        )
    elif resource.kind == "Rollout":
        resource.obj["spec"]["replicas"] = original_replicas
        logger.info(
            f"Scaling up {resource.kind} {resource.namespace}/{resource.name} from {replicas} to {original_replicas} replicas (uptime: {uptime}, downtime: {downtime})"
        )
    elif resource.kind == "ScaledObject":
        if ScaledObject.last_keda_pause_annotation_if_present in resource.annotations:
            if (
                resource.annotations[ScaledObject.last_keda_pause_annotation_if_present]
                is not None
            ):
                paused_replicas = resource.annotations[
                    ScaledObject.last_keda_pause_annotation_if_present
                ]
                resource.annotations[ScaledObject.keda_pause_annotation] = (
                    paused_replicas
                )
                resource.annotations[
                    ScaledObject.last_keda_pause_annotation_if_present
                ] = None
        else:
            resource.annotations[ScaledObject.keda_pause_annotation] = None
        logger.info(
            f"Unpausing {resource.kind} {resource.namespace}/{resource.name} (uptime: {uptime}, downtime: {downtime})"
        )
    elif resource.kind == "AutoscalingRunnerSet":
        resource.obj["spec"]["minRunners"] = original_replicas
        logger.info(
            f"Scaling up {resource.kind} {resource.namespace}/{resource.name} from {replicas} to {original_replicas} replicas (uptime: {uptime}, downtime: {downtime})"
        )
    else:
        resource.replicas = original_replicas
        logger.info(
            f"Scaling up {resource.kind} {resource.namespace}/{resource.name} from {replicas} to {original_replicas} replicas (uptime: {uptime}, downtime: {downtime})"
        )
    if enable_events:
        helper.add_event(
            resource,
            event_message,
            "ScaleUp",
            "Normal",
            dry_run,
        )
    resource.annotations[ORIGINAL_REPLICAS_ANNOTATION] = None


def scale_down(
    resource: NamespacedAPIObject,
    replicas: int,
    replicas_is_percentage,
    target_replicas: int,
    target_replicas_is_percentage,
    uptime,
    downtime,
    dry_run: bool,
    enable_events: bool,
):
    event_message = "Scaling down replicas"
    if target_replicas_is_percentage and resource.kind != "PodDisruptionBudget":
        logger.warning(
            f"Skipping scale down for {resource.kind} {resource.namespace}/{resource.name}: "
            f"percentage 'donwtime replicas' are supported when scaling only PodDisruptionBudget objects, "
            f"or when set on PodDisruptionBudget 'downscaler/downtime-replicas' resource annotation. "
            f"Use integer values in namespace 'downscaler/downtime-replicas' annotations and the --downscale-replicas argument to support scaling PDBs and other resources together. "
            f"(uptime: {uptime}, downtime: {downtime})"
        )
        raise ValueError(
            f"percentage 'donwtime-replicas' are not supported for {resource.kind}"
        )

    if resource.kind == "DaemonSet":
        if "nodeSelector" not in resource.obj["spec"]["template"]["spec"]:
            resource.obj["spec"]["template"]["spec"]["nodeSelector"] = {}
        resource.obj["spec"]["template"]["spec"]["nodeSelector"][
            "kube-downscaler-non-existent"
        ] = "true"
        logger.info(
            f"Suspending {resource.kind} {resource.namespace}/{resource.name} (uptime: {uptime}, downtime: {downtime})"
        )
        event_message = "Suspending DaemonSet"
    elif resource.kind in ["CronJob", "Job"]:
        resource.obj["spec"]["suspend"] = True
        logger.info(
            f"Suspending {resource.kind} {resource.namespace}/{resource.name} (uptime: {uptime}, downtime: {downtime})"
        )
        event_message = f"Suspending {resource.kind}"
    elif resource.kind == "PodDisruptionBudget":
        if "minAvailable" in resource.obj["spec"]:
            starting_replicas = (
                f"{replicas}%" if replicas_is_percentage else str(replicas)
            )
            target = (
                f"{target_replicas}%"
                if target_replicas_is_percentage
                else target_replicas
            )
            resource.obj["spec"]["minAvailable"] = target
            logger.info(
                f"Scaling down {resource.kind} {resource.namespace}/{resource.name} from {starting_replicas} to {target} minAvailable (uptime: {uptime}, downtime: {downtime})"
            )
        elif "maxUnavailable" in resource.obj["spec"]:
            starting_replicas = (
                f"{replicas}%" if replicas_is_percentage else str(replicas)
            )
            target = (
                f"{target_replicas}%"
                if target_replicas_is_percentage
                else target_replicas
            )
            resource.obj["spec"]["maxUnavailable"] = target
            logger.info(
                f"Scaling down {resource.kind} {resource.namespace}/{resource.name} from {starting_replicas} to {target} maxUnavailable (uptime: {uptime}, downtime: {downtime})"
            )
    elif resource.kind == "HorizontalPodAutoscaler":
        resource.obj["spec"]["minReplicas"] = target_replicas
        logger.info(
            f"Scaling down {resource.kind} {resource.namespace}/{resource.name} from {replicas} to {target_replicas} minReplicas (uptime: {uptime}, downtime: {downtime})"
        )
    elif resource.kind == "Rollout":
        resource.obj["spec"]["replicas"] = target_replicas
        logger.info(
            f"Scaling down {resource.kind} {resource.namespace}/{resource.name} from {replicas} to {target_replicas} replicas (uptime: {uptime}, downtime: {downtime})"
        )
    elif resource.kind == "ScaledObject":
        if ScaledObject.keda_pause_annotation in resource.annotations:
            if resource.annotations[ScaledObject.keda_pause_annotation] is not None:
                paused_replicas = resource.annotations[
                    ScaledObject.keda_pause_annotation
                ]
                resource.annotations[
                    ScaledObject.last_keda_pause_annotation_if_present
                ] = paused_replicas
        resource.annotations[ScaledObject.keda_pause_annotation] = str(target_replicas)
        logger.info(
            f"Pausing {resource.kind} {resource.namespace}/{resource.name} (uptime: {uptime}, downtime: {downtime})"
        )
        event_message = "Pausing KEDA ScaledObject"
    elif resource.kind == "AutoscalingRunnerSet":
        resource.obj["spec"]["minRunners"] = target_replicas
        logger.info(
            f"Scaling down {resource.kind} {resource.namespace}/{resource.name} from {replicas} to {target_replicas} replicas (uptime: {uptime}, downtime: {downtime})"
        )
    else:
        resource.replicas = target_replicas
        logger.info(
            f"Scaling down {resource.kind} {resource.namespace}/{resource.name} from {replicas} to {target_replicas} replicas (uptime: {uptime}, downtime: {downtime})"
        )
    if enable_events:
        helper.add_event(
            resource,
            event_message,
            "ScaleDown",
            "Normal",
            dry_run,
        )
    if replicas_is_percentage:
        resource.annotations[ORIGINAL_REPLICAS_ANNOTATION] = str(replicas) + "%"
    else:
        resource.annotations[ORIGINAL_REPLICAS_ANNOTATION] = str(replicas)


def get_annotation_value_as_positive_int(
    resource: NamespacedAPIObject, annotation_name: str
):
    raw_value = resource.annotations.get(annotation_name)
    if raw_value is None:
        return None, None
    return helper.parse_int_or_percent(
        raw_value, context="annotation", allow_negative=False
    )


def get_annotation_value_as_int(resource: NamespacedAPIObject, annotation_name: str):
    raw_value = resource.annotations.get(annotation_name)
    if raw_value is None:
        return None, None
    return helper.parse_int_or_percent(
        raw_value, context="annotation", allow_negative=True
    )


def autoscale_jobs_for_namespace(
    api,
    resource: NamespacedAPIObject,  # resource here is a namespace object
    upscale_period: str,
    downscale_period: str,
    default_uptime: str,
    default_downtime: str,
    forced_uptime: bool,
    forced_downtime: bool,
    matching_labels: FrozenSet[Pattern],
    dry_run: bool,
    now: datetime.datetime,
    grace_period: int,
    excluded_jobs: List[str],
    admission_controller: str,
    deployment_time_annotation: Optional[str] = None,
    namespace_excluded: bool = False,
    enable_events: bool = False,
):
    try:
        exclude = namespace_excluded

        if exclude:
            logger.debug(
                f"{resource.kind} {resource.name} was excluded from downscaling jobs"
            )
        else:
            ignore = False
            is_uptime = True

            upscale_period = resource.annotations.get(
                UPSCALE_PERIOD_ANNOTATION, upscale_period
            )
            downscale_period = resource.annotations.get(
                DOWNSCALE_PERIOD_ANNOTATION, downscale_period
            )

            if forced_uptime or exclude:
                uptime = "forced"
                downtime = "ignored"
                is_uptime = True
            elif forced_downtime and not exclude:
                uptime = "ignored"
                downtime = "forced"
                is_uptime = False
            elif upscale_period != "never" or downscale_period != "never":
                uptime = upscale_period
                downtime = downscale_period
                if matches_time_spec(now, uptime) and matches_time_spec(now, downtime):
                    logger.debug("Upscale and downscale periods overlap, do nothing")
                    ignore = True
                elif matches_time_spec(now, uptime):
                    is_uptime = True
                elif matches_time_spec(now, downtime):
                    is_uptime = False
                else:
                    ignore = True
                logger.debug(
                    f"Periods checked: upscale={upscale_period}, downscale={downscale_period}, ignore={ignore}, is_uptime={is_uptime}"
                )
            else:
                uptime = resource.annotations.get(UPTIME_ANNOTATION, default_uptime)
                downtime = resource.annotations.get(
                    DOWNTIME_ANNOTATION, default_downtime
                )
                is_uptime = matches_time_spec(now, uptime) and not matches_time_spec(
                    now, downtime
                )

            update_needed = False

            if not ignore and is_uptime:
                policy, operation = scale_up_jobs(
                    api,
                    resource,
                    uptime,
                    downtime,
                    admission_controller,
                    dry_run=dry_run,
                    enable_events=enable_events,
                )
                update_needed = True
            elif not ignore and not is_uptime:
                if within_grace_period_namespace(
                    resource, grace_period, now, deployment_time_annotation
                ):
                    logger.info(
                        f"{resource.kind}/{resource.name} within grace period ({grace_period}s), not scaling down jobs (yet)"
                    )
                else:
                    policy, operation = scale_down_jobs(
                        api,
                        resource,
                        uptime,
                        downtime,
                        admission_controller,
                        excluded_jobs,
                        matching_labels,
                        dry_run=dry_run,
                        enable_events=enable_events,
                    )
                    update_needed = True

            if update_needed:
                if dry_run:
                    logger.info(
                        f"**DRY-RUN**: would update {policy.kind}/{policy.name} for jobs scaling inside {resource.kind}/{resource.name}"
                    )
                else:
                    if (
                        operation == "scale_down"
                        and admission_controller == "gatekeeper"
                    ):
                        helper.call_with_exponential_backoff(
                            lambda: KubeDownscalerJobsConstraint(api, policy).create(),
                            context_msg="creating KubeDownscalerJobsConstraint",
                        )
                        logger.debug("KubeDownscalerJobsConstraint Created")
                    elif (
                        operation == "scale_down" and admission_controller == "kyverno"
                    ):
                        logger.debug("Creating KubeDownscalerJobsPolicy")
                        helper.call_with_exponential_backoff(
                            lambda: KubeDownscalerJobsPolicy(api, policy).create(),
                            context_msg="creating KubeDownscalerJobsPolicy",
                        )
                        logger.debug("Kyverno KubeDownscalerJobsPolicy Created")
                    elif operation == "scale_up":
                        helper.call_with_exponential_backoff(
                            lambda: policy.delete(),
                            context_msg="deleting Kyverno Policy",
                        )
                        logger.debug("Kyverno Policy Correctly Deleted")
                    elif operation == "kyverno_update":
                        helper.call_with_exponential_backoff(
                            lambda: KubeDownscalerJobsPolicy(api, policy).update(),
                            context_msg="updating Kyverno Policy",
                        )
                        logger.debug("Kyverno Policy Correctly Updated")
                    elif operation == "no_scale":
                        pass
                    else:
                        logger.error(
                            f"there was an error scaling scaling inside {resource.kind}/{resource.name}"
                        )

    except Exception as e:
        logger.exception(f"Failed to process {resource.kind} {resource.name}: {e}")


def autoscale_resource(
    resource: NamespacedAPIObject,
    upscale_period: str,
    downscale_period: str,
    default_uptime: str,
    default_downtime: str,
    forced_uptime: bool,
    forced_downtime: bool,
    upscale_target_only: bool,
    max_retries_on_conflict: int,
    api: HTTPClient,
    kind: NamespacedAPIObject,
    dry_run: bool,
    now: datetime.datetime,
    grace_period: int = 0,
    downtime_replicas: int = 0,
    is_downtime_replicas_percentage: bool = False,
    namespace_excluded=False,
    deployment_time_annotation: Optional[str] = None,
    enable_events: bool = False,
    matching_labels: FrozenSet[Pattern] = frozenset(),
):
    try:
        exclude = (
            namespace_excluded
            or ignore_if_labels_dont_match(resource, matching_labels)
            or ignore_resource(resource, now)
        )
        original_replicas, is_original_replicas_percentage = (
            get_annotation_value_as_int(resource, ORIGINAL_REPLICAS_ANNOTATION)
        )

        (
            downtime_replicas_from_annotation,
            is_downtime_replicas_from_annotation_percentage,
        ) = get_annotation_value_as_positive_int(resource, DOWNTIME_REPLICAS_ANNOTATION)

        if downtime_replicas_from_annotation is not None:
            downtime_replicas = downtime_replicas_from_annotation

        if is_downtime_replicas_from_annotation_percentage is not None:
            is_downtime_replicas_percentage = (
                is_downtime_replicas_from_annotation_percentage
            )

        exclude_condition = define_scope(
            exclude, original_replicas, upscale_target_only
        )

        if exclude_condition:
            logger.debug(
                f"{resource.kind} {resource.namespace}/{resource.name} was excluded"
            )
        else:
            ignore = False
            is_uptime = True

            upscale_period = resource.annotations.get(
                UPSCALE_PERIOD_ANNOTATION, upscale_period
            )
            downscale_period = resource.annotations.get(
                DOWNSCALE_PERIOD_ANNOTATION, downscale_period
            )
            if forced_uptime or (exclude and original_replicas):
                uptime = "forced"
                downtime = "ignored"
                is_uptime = True
            elif forced_downtime and not (exclude and original_replicas):
                uptime = "ignored"
                downtime = "forced"
                is_uptime = False
            elif upscale_period != "never" or downscale_period != "never":
                uptime = upscale_period
                downtime = downscale_period
                if matches_time_spec(now, uptime) and matches_time_spec(now, downtime):
                    logger.debug("Upscale and downscale periods overlap, do nothing")
                    ignore = True
                elif matches_time_spec(now, uptime):
                    is_uptime = True
                elif matches_time_spec(now, downtime):
                    is_uptime = False
                else:
                    ignore = True
                logger.debug(
                    f"Periods checked: upscale={upscale_period}, downscale={downscale_period}, ignore={ignore}, is_uptime={is_uptime}"
                )
            else:
                uptime = resource.annotations.get(UPTIME_ANNOTATION, default_uptime)
                downtime = resource.annotations.get(
                    DOWNTIME_ANNOTATION, default_downtime
                )
                is_uptime = matches_time_spec(now, uptime) and not matches_time_spec(
                    now, downtime
                )

            replicas, replicas_is_percentage = get_replicas(
                resource, original_replicas, uptime
            )
            update_needed = False

            if (
                not ignore
                and is_uptime
                and replicas == downtime_replicas
                and original_replicas
                and (original_replicas > 0 or original_replicas == -1)
            ):
                try:
                    scale_up(
                        resource,
                        replicas,
                        replicas_is_percentage,
                        original_replicas,
                        is_original_replicas_percentage,
                        uptime,
                        downtime,
                        dry_run=dry_run,
                        enable_events=enable_events,
                    )
                    update_needed = True
                except ValueError:
                    update_needed = False
            elif (
                not ignore
                and not is_uptime
                and (replicas > 0 and replicas > downtime_replicas or replicas == -1)
            ):
                if within_grace_period(
                    resource, grace_period, now, deployment_time_annotation
                ):
                    logger.info(
                        f"{resource.kind} {resource.namespace}/{resource.name} within grace period ({grace_period}s), not scaling down (yet)"
                    )
                else:
                    try:
                        scale_down(
                            resource,
                            replicas,
                            replicas_is_percentage,
                            downtime_replicas,
                            is_downtime_replicas_percentage,
                            uptime,
                            downtime,
                            dry_run=dry_run,
                            enable_events=enable_events,
                        )
                        update_needed = True
                    except ValueError:
                        update_needed = False

            if update_needed:
                if dry_run:
                    logger.info(
                        f"**DRY-RUN**: would update {resource.kind} {resource.namespace}/{resource.name}"
                    )
                else:
                    helper.call_with_exponential_backoff(
                        lambda: resource.update(),
                        context_msg=f"patching {kind.endpoint} {resource.namespace}/{resource.name}",
                    )
    except Exception as e:
        if (
            isinstance(e, HTTPError)
            and "the object has been modified" in str(e).lower()
        ):
            logger.warning(
                f"Unable to process {resource.kind} {resource.namespace}/{resource.name} because it was recently modified"
            )
            if max_retries_on_conflict > 0:
                logger.info(
                    f"Retrying processing {resource.kind} {resource.namespace}/{resource.name} (Remaining Retries: {max_retries_on_conflict})"
                )
                max_retries_on_conflict = max_retries_on_conflict - 1
                refreshed_resource = get_resource(
                    kind, api, resource.namespace, resource.name
                )
                if refreshed_resource is not None:
                    autoscale_resource(
                        refreshed_resource,
                        upscale_period,
                        downscale_period,
                        default_uptime,
                        default_downtime,
                        forced_uptime,
                        forced_downtime,
                        upscale_target_only,
                        max_retries_on_conflict,
                        api,
                        kind,
                        dry_run,
                        now,
                        grace_period,
                        downtime_replicas,
                        is_downtime_replicas_percentage,
                        namespace_excluded=namespace_excluded,
                        deployment_time_annotation=deployment_time_annotation,
                        enable_events=enable_events,
                        matching_labels=matching_labels,
                    )
                else:
                    logger.warning(
                        f"Retry process failed for {resource.kind} {resource.namespace}/{resource.name} because the resource cannot be found, it may have been deleted from the cluster"
                    )
            else:
                logger.warning(
                    f"Will retry processing {resource.kind} {resource.namespace}/{resource.name} in the next iteration, unless the --once argument is specified"
                )
        elif isinstance(e, HTTPError) and "not found" in str(e).lower():
            logger.info(
                f"While waiting to process {resource.kind} {resource.namespace}/{resource.name}, the resource was removed from the cluster"
            )
        else:
            logger.exception(
                f"Failed to process {resource.kind} {resource.namespace}/{resource.name}: {e}"
            )


def autoscale_resources(
    api: HTTPClient,
    kind: NamespacedAPIObject,
    namespace: FrozenSet[str],
    namespace_to_namespace_obj: dict[str, Any],
    exclude_namespaces: FrozenSet[Pattern],
    exclude_names: FrozenSet[str],
    matching_labels: FrozenSet[Pattern],
    upscale_period: str,
    downscale_period: str,
    default_uptime: str,
    default_downtime: str,
    forced_uptime: bool,
    upscale_target_only: bool,
    constrained_downscaler: bool,
    max_retries_on_conflict: int,
    dry_run: bool,
    now: datetime.datetime,
    grace_period: int,
    downtime_replicas: int,
    is_downtime_replicas_percentage: bool,
    deployment_time_annotation: Optional[str] = None,
    enable_events: bool = False,
):
    resources_by_namespace = collections.defaultdict(list)
    resources, exclude_namespaces = get_resources(
        kind, api, namespace, exclude_namespaces
    )

    try:
        for resource in resources:
            if resource.name in exclude_names:
                logger.debug(
                    f"{resource.kind} {resource.namespace}/{resource.name} was excluded (name matches exclusion list)"
                )
                continue
            if resource.kind == "Job" and "ownerReferences" in resource.metadata:
                logger.debug(
                    f"{resource.kind} {resource.namespace}/{resource.name} was excluded (Job with ownerReferences)"
                )
                continue
            resources_by_namespace[resource.namespace].append(resource)
    except requests.HTTPError as e:
        if e.response.status_code == 404:
            logger.debug(f"No {kind.endpoint} found (404)")
        elif e.response.status_code == 403:
            logger.error(
                f"Not authorized to perform a cluster wide query to retrieve {kind.endpoint} check your RBAC settings (403)"
            )
        else:
            raise e

    for current_namespace, resources in sorted(resources_by_namespace.items()):
        if any(
            [pattern.fullmatch(current_namespace) for pattern in exclude_namespaces]
        ):
            logger.debug(
                f"Namespace {current_namespace} was excluded (exclusion list regex matches)"
            )
            continue

        logger.debug(
            f"Processing {len(resources)} {kind.endpoint} in namespace {current_namespace}.."
        )

        # Override defaults with (optional) annotations from Namespace
        namespace_obj = namespace_to_namespace_obj[current_namespace]

        excluded = ignore_resource(namespace_obj, now)

        default_uptime_for_namespace = namespace_obj.annotations.get(
            UPTIME_ANNOTATION, default_uptime
        )
        default_downtime_for_namespace = namespace_obj.annotations.get(
            DOWNTIME_ANNOTATION, default_downtime
        )
        (
            default_downtime_replicas_for_namespace,
            is_default_downtime_replicas_for_namespace_percentage,
        ) = get_annotation_value_as_positive_int(
            namespace_obj, DOWNTIME_REPLICAS_ANNOTATION
        )

        if default_downtime_replicas_for_namespace is None:
            default_downtime_replicas_for_namespace = downtime_replicas

        if is_default_downtime_replicas_for_namespace_percentage is None:
            is_default_downtime_replicas_for_namespace_percentage = (
                is_downtime_replicas_percentage
            )

        upscale_period_for_namespace = namespace_obj.annotations.get(
            UPSCALE_PERIOD_ANNOTATION, upscale_period
        )
        downscale_period_for_namespace = namespace_obj.annotations.get(
            DOWNSCALE_PERIOD_ANNOTATION, downscale_period
        )
        forced_uptime_value_for_namespace = str(
            namespace_obj.annotations.get(FORCE_UPTIME_ANNOTATION, forced_uptime)
        )
        forced_downtime_value_for_namespace = str(
            namespace_obj.annotations.get(FORCE_DOWNTIME_ANNOTATION, False)
        )
        if forced_uptime_value_for_namespace.lower() == "true":
            forced_uptime_for_namespace = True
        elif forced_uptime_value_for_namespace.lower() == "false":
            forced_uptime_for_namespace = False
        elif forced_uptime_value_for_namespace:
            forced_uptime_for_namespace = matches_time_spec(
                now, forced_uptime_value_for_namespace
            )
        else:
            forced_uptime_for_namespace = False

        if forced_downtime_value_for_namespace.lower() == "true":
            forced_downtime_for_namespace = True
        elif forced_downtime_value_for_namespace.lower() == "false":
            forced_downtime_for_namespace = False
        elif forced_downtime_value_for_namespace:
            forced_downtime_for_namespace = matches_time_spec(
                now, forced_downtime_value_for_namespace
            )
        else:
            forced_downtime_for_namespace = False

        for resource in resources:
            autoscale_resource(
                resource,
                upscale_period_for_namespace,
                downscale_period_for_namespace,
                default_uptime_for_namespace,
                default_downtime_for_namespace,
                forced_uptime_for_namespace,
                forced_downtime_for_namespace,
                upscale_target_only,
                max_retries_on_conflict,
                api,
                kind,
                dry_run,
                now,
                grace_period,
                default_downtime_replicas_for_namespace,
                is_default_downtime_replicas_for_namespace_percentage,
                namespace_excluded=excluded,
                deployment_time_annotation=deployment_time_annotation,
                enable_events=enable_events,
                matching_labels=matching_labels,
            )


def apply_kubedownscalerjobsconstraint_crd(excluded_names, matching_labels, api):
    kube_downscaler_jobs_constraint_crd = CustomResourceDefinition.objects(
        api
    ).get_or_none(name="kubedownscalerjobsconstraint.constraints.gatekeeper.sh")
    obj = ConstraintTemplate.create_constraint_template_crd(
        excluded_names, matching_labels
    )
    if kube_downscaler_jobs_constraint_crd is not None:
        if obj == kube_downscaler_jobs_constraint_crd:
            logger.debug(
                "kubedownscalerjobsconstraint.constraints.gatekeeper.sh CRD already present"
            )
            return
        else:
            helper.call_with_exponential_backoff(
                lambda: ConstraintTemplate(api, obj).update(obj),
                context_msg="patching kubedownscalerjobsconstraint.constraints.gatekeeper.sh CRD",
            )
            logger.debug(
                "kubedownscalerjobsconstraint.constraints.gatekeeper.sh CRD updated"
            )
    else:
        helper.call_with_exponential_backoff(
            lambda: ConstraintTemplate(api, obj).create(),
            context_msg="creating kubedownscalerjobsconstraint.constraints.gatekeeper.sh CRD",
        )
        logger.debug(
            "kubedownscalerjobsconstraint.constraints.gatekeeper.sh CRD created"
        )
        time.sleep(0.02)


def gatekeeper_constraint_template_crd_exist(api) -> bool:
    constraint_template_crd = CustomResourceDefinition.objects(api).get_or_none(
        name="constrainttemplates.templates.gatekeeper.sh"
    )

    if constraint_template_crd is None:
        logger.error(
            "constrainttemplates.templates.gatekeeper.sh CRD not found inside the cluster"
        )
        return False
    else:
        logger.debug(
            "constrainttemplates.templates.gatekeeper.sh CRD present inside the cluster"
        )
        return True


def gatekeeper_healthy(api) -> bool:
    gatekeeper_audit = (
        Deployment.objects(api)
        .filter(namespace="gatekeeper-system")
        .get_or_none(name="gatekeeper-audit")
    )
    gatekeeper_controller_manager = (
        Deployment.objects(api)
        .filter(namespace="gatekeeper-system")
        .get_or_none(name="gatekeeper-controller-manager")
    )

    kubedownscalerjobsconstraint = CustomResourceDefinition.objects(api).get_or_none(
        name="kubedownscalerjobsconstraint.constraints.gatekeeper.sh"
    )

    if gatekeeper_audit is None or gatekeeper_controller_manager is None:
        logger.debug(
            'Health Check: gatekeeper deployments not found inside the default "gatekeeper-system" '
            "namespace. While this is not a problem, downscaling jobs policy may not be enforced unless "
            "gatekeeper is installed and healthy inside another namespace"
        )
    else:
        if (
            gatekeeper_audit.obj["spec"]["replicas"] > 0
            and gatekeeper_controller_manager.obj["spec"]["replicas"] > 0
        ):
            logger.debug(
                'Health Check: gatekeeper deployments are healthy inside the "gatekeeper-system" namespace'
            )
        else:
            logger.debug(
                'Health Check: gatekeeper deployments are not healthy inside the "gatekeeper-system" namespace '
                "downscaling jobs policy may not be enforced"
            )

    if kubedownscalerjobsconstraint is None:
        logger.error(
            "kubedownscalerjobsconstraint.constraints.gatekeeper.sh CRD not found inside the cluster"
        )
        return False
    else:
        return True


def kyverno_healthy(api):
    kyverno_admission_controller = (
        Deployment.objects(api)
        .filter(namespace="kyverno")
        .get_or_none(name="kyverno-admission-controller")
        .obj
    )
    kyverno_background_controller = (
        Deployment.objects(api)
        .filter(namespace="kyverno")
        .get_or_none(name="kyverno-background-controller")
        .obj
    )
    kyverno_policy_crd = CustomResourceDefinition.objects(api).get_or_none(
        name="policies.kyverno.io"
    )

    if kyverno_admission_controller is None or kyverno_background_controller is None:
        logger.debug(
            'Health Check: kyverno deployments not found inside the default "kyverno" '
            "namespace. While this is not a problem, downscaling jobs policy may not be enforced unless "
            "kyverno is installed and healthy inside another namespace"
        )
    else:
        if (
            kyverno_admission_controller["spec"]["replicas"] > 0
            and kyverno_background_controller["spec"]["replicas"] > 0
        ):
            logger.debug(
                'Health Check: kyverno deployments are healthy inside the "kyverno" namespace'
            )
        else:
            logger.debug(
                'Health Check: kyverno deployments are not healthy inside the "kyverno" namespace '
                "downscaling jobs policy may not be enforced"
            )

    if kyverno_policy_crd is None:
        logger.error("policies.kyverno.io CRD not found inside the cluster")
        return False
    else:
        return True


def autoscale_jobs(
    api,
    namespaces: FrozenSet[str],
    namespace_to_namespace_obj: dict[str, Any],
    exclude_namespaces: FrozenSet[Pattern],
    upscale_period: str,
    downscale_period: str,
    default_uptime: str,
    default_downtime: str,
    forced_uptime: bool,
    matching_labels: FrozenSet[Pattern],
    dry_run: bool,
    now: datetime.datetime,
    grace_period: int,
    admission_controller: str,
    exclude_names: FrozenSet[str],
    deployment_time_annotation: Optional[str] = None,
    enable_events: bool = False,
):
    if admission_controller != "" and admission_controller in ADMISSION_CONTROLLERS:
        if (
            admission_controller == "gatekeeper"
            and gatekeeper_constraint_template_crd_exist(api)
        ):
            apply_kubedownscalerjobsconstraint_crd(exclude_names, matching_labels, api)
            if admission_controller == "gatekeeper" and not gatekeeper_healthy(api):
                logger.error(
                    "unable to scale jobs, there was a problem applying kubedownscalerjobsconstraint crd or it was deleted"
                    " from the cluster. The crd will be automatically re-applied"
                )
                return
        elif (
            admission_controller == "gatekeeper"
            and not gatekeeper_constraint_template_crd_exist(api)
        ):
            logger.warning(
                "unable to scale jobs with gatekeeper until you install constrainttemplates.templates.gatekeeper.sh "
                "CRD"
            )
            return

        if admission_controller == "kyverno" and not kyverno_healthy(api):
            logger.error("unable to scale jobs")
            return

        if len(namespaces) >= 1:
            namespaces = namespaces
        else:
            namespaces = frozenset(Namespace.objects(api).iterator())

        excluded_jobs = []

        for name in exclude_names:
            excluded_jobs.append(name)

        for current_namespace in namespaces:
            if any(
                [pattern.fullmatch(current_namespace) for pattern in exclude_namespaces]
            ):
                logger.debug(
                    f"Namespace {current_namespace} was excluded from job scaling (exclusion list regex matches)"
                )
                continue

            logger.debug(f"Processing {current_namespace} for job scaling..")

            # Override defaults with (optional) annotations from Namespace
            namespace_obj = namespace_to_namespace_obj[current_namespace]

            excluded = ignore_resource(current_namespace, now)

            default_uptime_for_namespace = namespace_obj.annotations.get(
                UPTIME_ANNOTATION, default_uptime
            )
            default_downtime_for_namespace = namespace_obj.annotations.get(
                DOWNTIME_ANNOTATION, default_downtime
            )

            upscale_period_for_namespace = namespace_obj.annotations.get(
                UPSCALE_PERIOD_ANNOTATION, upscale_period
            )
            downscale_period_for_namespace = namespace_obj.annotations.get(
                DOWNSCALE_PERIOD_ANNOTATION, downscale_period
            )
            forced_uptime_value_for_namespace = str(
                namespace_obj.annotations.get(FORCE_UPTIME_ANNOTATION, forced_uptime)
            )
            forced_downtime_value_for_namespace = str(
                namespace_obj.annotations.get(FORCE_DOWNTIME_ANNOTATION, False)
            )
            if forced_uptime_value_for_namespace.lower() == "true":
                forced_uptime_for_namespace = True
            elif forced_uptime_value_for_namespace.lower() == "false":
                forced_uptime_for_namespace = False
            elif forced_uptime_value_for_namespace:
                forced_uptime_for_namespace = matches_time_spec(
                    now, forced_uptime_value_for_namespace
                )
            else:
                forced_uptime_for_namespace = False

            if forced_downtime_value_for_namespace.lower() == "true":
                forced_downtime_for_namespace = True
            elif forced_downtime_value_for_namespace.lower() == "false":
                forced_downtime_for_namespace = False
            elif forced_downtime_value_for_namespace:
                forced_downtime_for_namespace = matches_time_spec(
                    now, forced_downtime_value_for_namespace
                )
            else:
                forced_downtime_for_namespace = False

            autoscale_jobs_for_namespace(
                api,
                current_namespace,
                upscale_period_for_namespace,
                downscale_period_for_namespace,
                default_uptime_for_namespace,
                default_downtime_for_namespace,
                forced_uptime_for_namespace,
                forced_downtime_for_namespace,
                matching_labels,
                dry_run,
                now,
                grace_period,
                excluded_jobs,
                admission_controller=admission_controller,
                deployment_time_annotation=deployment_time_annotation,
                namespace_excluded=excluded,
                enable_events=enable_events,
            )
    else:
        if admission_controller == "":
            logger.warning(
                "admission controller arg was not specified, unable to scale jobs"
            )
        else:
            logger.warning(
                "admission controller arg is not written correctly or not supported"
            )


def scale(
    namespaces: FrozenSet[str],
    upscale_period: str,
    downscale_period: str,
    default_uptime: str,
    default_downtime: str,
    upscale_target_only: bool,
    include_resources: FrozenSet[str],
    exclude_namespaces: FrozenSet[Pattern],
    exclude_deployments: FrozenSet[str],
    dry_run: bool,
    grace_period: int,
    admission_controller: str,
    constrained_downscaler: bool,
    api_server_timeout: int,
    max_retries_on_conflict: int,
    downtime_replicas: int = 0,
    is_downtime_replicas_percentage: bool = False,
    deployment_time_annotation: Optional[str] = None,
    enable_events: bool = False,
    matching_labels: FrozenSet[Pattern] = frozenset(),
):
    api = helper.get_kube_api(api_server_timeout)

    now = datetime.datetime.now(datetime.timezone.utc)
    namespace_to_namespace_obj = get_namespace_to_namespace_obj(api, namespaces)
    forced_uptime = pods_force_uptime(api, namespaces)

    for clazz in RESOURCE_CLASSES:
        plural = clazz.endpoint
        if plural in include_resources:
            if (
                scale_jobs_without_admission_controller(
                    plural, admission_controller, constrained_downscaler
                )
                or plural != "jobs"
            ):
                autoscale_resources(
                    api,
                    clazz,
                    namespaces,
                    namespace_to_namespace_obj,
                    exclude_namespaces,
                    exclude_deployments,
                    matching_labels,
                    upscale_period,
                    downscale_period,
                    default_uptime,
                    default_downtime,
                    forced_uptime,
                    upscale_target_only,
                    constrained_downscaler,
                    max_retries_on_conflict,
                    dry_run,
                    now,
                    grace_period,
                    downtime_replicas,
                    is_downtime_replicas_percentage,
                    deployment_time_annotation,
                    enable_events,
                )
            else:
                autoscale_jobs(
                    api,
                    namespaces,
                    namespace_to_namespace_obj,
                    exclude_namespaces,
                    upscale_period,
                    downscale_period,
                    default_uptime,
                    default_downtime,
                    forced_uptime,
                    matching_labels,
                    dry_run,
                    now,
                    grace_period,
                    admission_controller,
                    exclude_deployments,
                    deployment_time_annotation,
                    enable_events,
                )
