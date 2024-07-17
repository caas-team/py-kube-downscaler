import collections
import datetime
import logging
import time
import requests
from typing import FrozenSet
from typing import Optional
from typing import Pattern

import pykube
from pykube import CronJob
from pykube import Deployment
from pykube import HorizontalPodAutoscaler
from pykube import Namespace
from pykube import StatefulSet
from pykube import Job
from pykube import CustomResourceDefinition
from pykube.objects import NamespacedAPIObject, APIObject
from pykube import DaemonSet
from pykube.objects import NamespacedAPIObject, PodDisruptionBudget

from kube_downscaler import helper
from kube_downscaler.helper import matches_time_spec
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
    Job
]

TIMESTAMP_FORMATS = [
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d",
]

ADMISSION_CONTROLLERS = [
    "gatekeeper",
    "kyverno"
]

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


def within_grace_period(
    resource,
    grace_period: int,
    now: datetime.datetime,
    deployment_time_annotation: Optional[str] = None,
):
    update_time = parse_time(resource.metadata["creationTimestamp"])

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

def pods_force_uptime(api, namespace: str):
    """Return True if there are any running pods which require the deployments to be scaled back up."""
    for pod in pykube.Pod.objects(api).filter(namespace=(namespace or pykube.all)):
        if pod.obj.get("status", {}).get("phase") in ("Succeeded", "Failed"):
            continue
        if pod.annotations.get(FORCE_UPTIME_ANNOTATION, "").lower() == "true":
            logger.info(f"Forced uptime because of {pod.namespace}/{pod.name}")
            return True
    return False

def scale_jobs_without_admission_controller(plural, admission_controller):
    return plural == "jobs" and admission_controller == ""

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
) -> int:
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
            logger.debug(
                f"{resource.kind} {resource.namespace}/{resource.name} has {replicas} minAvailable (original: {original_replicas}, uptime: {uptime})"
            )
        elif "maxUnavailable" in resource.obj["spec"]:
            replicas = resource.obj["spec"]["maxUnavailable"]
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
            kube_downscaler_node_selector_dict = resource.obj["spec"]["template"]["spec"]["nodeSelector"]
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
    else:
        replicas = resource.replicas
        logger.debug(
            f"{resource.kind} {resource.namespace}/{resource.name} has {replicas} replicas (original: {original_replicas}, uptime: {uptime})"
        )
    return replicas

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
        policy = KubeDownscalerJobsConstraint.objects(api).get_or_none(name=resource.name)
        if policy is not None:
            operation = "scale_up"
            logger.info(
                f"Unsuspending jobs for {resource.kind}/{resource.name} (uptime: {uptime}, downtime: {downtime})"
            )
        else:
            operation = "no_scale"
    if admission_controller == "kyverno":
        policy_name = "kube-downscaler-jobs-policy"
        policy = KubeDownscalerJobsPolicy.objects(api).filter(namespace=resource.name).get_or_none(name=policy_name)
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
        excluded_jobs: [str],
        matching_labels: FrozenSet[Pattern],
        dry_run: bool,
        enable_events: bool,
) -> dict:
    policy: APIObject = None
    operation = "no_scale"
    obj = None

    event_message = "Scaling down jobs"
    if admission_controller == "gatekeeper":
        policy = KubeDownscalerJobsConstraint.objects(api).get_or_none(name=resource.name)
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
        first_element = next(iter(matching_labels), None)
        first_element_str = first_element.pattern
        if first_element_str == "":
            has_matching_labels_arg = False
        else:
            has_matching_labels_arg = True

        policy_name = "kube-downscaler-jobs-policy"
        policy = KubeDownscalerJobsPolicy.objects(api).filter(namespace=resource.name).get_or_none(name=policy_name)

        if policy is None:
            if has_matching_labels_arg:
                obj = KubeDownscalerJobsPolicy.create_job_policy_with_matching_labels(resource.name, matching_labels)
            else:
                obj = KubeDownscalerJobsPolicy.create_job_policy(resource.name)

            if len(excluded_jobs) > 0:
                obj = KubeDownscalerJobsPolicy.append_excluded_jobs_condition(obj, excluded_jobs, has_matching_labels_arg)
            operation = "scale_down"
            logger.info(
                f"Suspending jobs for {resource.kind}/{resource.name} (uptime: {uptime}, downtime: {downtime})"
            )
        else:
            if has_matching_labels_arg and policy.type == "with-matching-labels":
                obj = policy
                operation = "no_scale"
                logging.debug("No need to update kyverno policy, correctly found a policy with matching label")
            elif has_matching_labels_arg and policy.type != "with-matching-labels":
                operation = "kyverno_update"
                obj = KubeDownscalerJobsPolicy.create_job_policy_with_matching_labels(resource.name, matching_labels)
                if len(excluded_jobs) > 0:
                    obj = KubeDownscalerJobsPolicy.append_excluded_jobs_condition(obj, excluded_jobs,
                                                                                  has_matching_labels_arg)
                logging.debug("Update needed for kyverno policy, found a policy without matching label but need a policy with matching label")
            elif not has_matching_labels_arg and policy.type == "without-matching-labels":
                obj = policy
                operation = "no_scale"
                logging.debug("No need to update kyverno policy, correctly found a policy without matching label")
            elif not has_matching_labels_arg and policy.type != "without-matching-labels":
                operation = "kyverno_update"
                obj = KubeDownscalerJobsPolicy.create_job_policy(resource.name)
                if len(excluded_jobs) > 0:
                    obj = KubeDownscalerJobsPolicy.append_excluded_jobs_condition(obj, excluded_jobs,
                                                                                  has_matching_labels_arg)
                logging.debug("Update needed for kyverno policy, found a policy with matching label but need a policy without matching label")
            else:
                obj = policy
                operation = "no_scale"
                logging.debug("No Update Needed For Policy, all conditions were not met")
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
    original_replicas: int,
    uptime,
    downtime,
    dry_run: bool,
    enable_events: bool,
):
    event_message = "Scaling up replicas"
    if resource.kind == "DaemonSet":
        resource.obj["spec"]["template"]["spec"]["nodeSelector"]["kube-downscaler-non-existent"] = None
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
            resource.obj["spec"]["minAvailable"] = original_replicas
            logger.info(
                f"Scaling up {resource.kind} {resource.namespace}/{resource.name} from {replicas} to {original_replicas} minAvailable (uptime: {uptime}, downtime: {downtime})"
            )
        elif "maxUnavailable" in resource.obj["spec"]:
            resource.obj["spec"]["maxUnavailable"] = original_replicas
            logger.info(
                f"Scaling up {resource.kind} {resource.namespace}/{resource.name} from {replicas} to {original_replicas} maxUnavailable (uptime: {uptime}, downtime: {downtime})"
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
        if resource.annotations[ScaledObject.last_keda_pause_annotation_if_present] is not None:
            paused_replicas = resource.annotations[ScaledObject.last_keda_pause_annotation_if_present]
            resource.annotations[ScaledObject.keda_pause_annotation] = paused_replicas
            resource.annotations[ScaledObject.last_keda_pause_annotation_if_present] = None
        else:
            resource.annotations[ScaledObject.keda_pause_annotation] = None
        logger.info(
            f"Unpausing {resource.kind} {resource.namespace}/{resource.name} (uptime: {uptime}, downtime: {downtime})"
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
    target_replicas: int,
    uptime,
    downtime,
    dry_run: bool,
    enable_events: bool,
):
    event_message = "Scaling down replicas"
    if resource.kind == "DaemonSet":
        if "nodeSelector" not in resource.obj["spec"]["template"]["spec"]:
            resource.obj["spec"]["template"]["spec"]["nodeSelector"] = {}
        resource.obj["spec"]["template"]["spec"]["nodeSelector"]["kube-downscaler-non-existent"] = "true"
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
            resource.obj["spec"]["minAvailable"] = target_replicas
            logger.info(
                f"Scaling down {resource.kind} {resource.namespace}/{resource.name} from {replicas} to {target_replicas} minAvailable (uptime: {uptime}, downtime: {downtime})"
            )
        elif "maxUnavailable" in resource.obj["spec"]:
            resource.obj["spec"]["maxUnavailable"] = target_replicas
            logger.info(
                f"Scaling down {resource.kind} {resource.namespace}/{resource.name} from {replicas} to {target_replicas} maxUnavailable (uptime: {uptime}, downtime: {downtime})"
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
        if resource.annotations[ScaledObject.keda_pause_annotation] is not None:
            paused_replicas = resource.annotations[ScaledObject.keda_pause_annotation]
            resource.annotations[ScaledObject.last_keda_pause_annotation_if_present] = paused_replicas
        resource.annotations[ScaledObject.keda_pause_annotation] = "0"
        logger.info(
            f"Pausing {resource.kind} {resource.namespace}/{resource.name} (uptime: {uptime}, downtime: {downtime})"
        )
        event_message = "Pausing KEDA ScaledObject"
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
    resource.annotations[ORIGINAL_REPLICAS_ANNOTATION] = str(replicas)


def get_annotation_value_as_int(
    resource: NamespacedAPIObject, annotation_name: str
) -> Optional[int]:
    value = resource.annotations.get(annotation_name)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError as e:
        raise ValueError(
            f"Could not read annotation '{annotation_name}' as integer: {e}"
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
        excluded_jobs: [str],
        admission_controller: str,
        deployment_time_annotation: Optional[str] = None,
        namespace_excluded: bool = False,
        enable_events: bool = False,
):
    try:

        exclude = (
                namespace_excluded
        )

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

            if (
                    not ignore
                    and is_uptime
            ):

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
            elif (
                    not ignore
                    and not is_uptime
            ):
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
                    if operation == "scale_down" and admission_controller == "gatekeeper":
                        logger.debug("Creating KubeDownscalerJobsConstraint")
                        KubeDownscalerJobsConstraint(api, policy).create()
                    elif operation == "scale_down" and admission_controller == "kyverno":
                        logger.debug("Creating KubeDownscalerJobsPolicy")
                        KubeDownscalerJobsPolicy(api, policy).create()
                    elif operation == "scale_up":
                        policy.delete()
                    elif operation == "kyverno_update":
                        KubeDownscalerJobsPolicy(api, policy).update()
                        logger.debug("Kyverno Policy Correctly Updated")
                    elif operation == "no_scale":
                        pass
                    else:
                        logging.error(f"there was an error scaling scaling inside {resource.kind}/{resource.name}")

    except Exception as e:
        logger.exception(
            f"Failed to process {resource.kind} {resource.name}: {e}"
        )

def autoscale_resource(
    resource: NamespacedAPIObject,
    upscale_period: str,
    downscale_period: str,
    default_uptime: str,
    default_downtime: str,
    forced_uptime: bool,
    forced_downtime: bool,
    dry_run: bool,
    now: datetime.datetime,
    grace_period: int = 0,
    downtime_replicas: int = 0,
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
        original_replicas = get_annotation_value_as_int(
            resource, ORIGINAL_REPLICAS_ANNOTATION
        )
        downtime_replicas_from_annotation = get_annotation_value_as_int(
            resource, DOWNTIME_REPLICAS_ANNOTATION
        )
        if downtime_replicas_from_annotation is not None:
            downtime_replicas = downtime_replicas_from_annotation

        if exclude and not original_replicas:
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

            replicas = get_replicas(resource, original_replicas, uptime)
            update_needed = False

            if (
                not ignore
                and is_uptime
                and replicas == downtime_replicas
                and original_replicas
                and original_replicas > 0
            ):
                scale_up(
                    resource,
                    replicas,
                    original_replicas,
                    uptime,
                    downtime,
                    dry_run=dry_run,
                    enable_events=enable_events,
                )
                update_needed = True
            elif (
                not ignore
                and not is_uptime
                and replicas > 0
                and replicas > downtime_replicas
            ):
                if within_grace_period(
                    resource, grace_period, now, deployment_time_annotation
                ):
                    logger.info(
                        f"{resource.kind} {resource.namespace}/{resource.name} within grace period ({grace_period}s), not scaling down (yet)"
                    )
                else:
                    scale_down(
                        resource,
                        replicas,
                        downtime_replicas,
                        uptime,
                        downtime,
                        dry_run=dry_run,
                        enable_events=enable_events,
                    )
                    update_needed = True

            if update_needed:
                if dry_run:
                    logger.info(
                        f"**DRY-RUN**: would update {resource.kind} {resource.namespace}/{resource.name}"
                    )
                else:
                    resource.update()
    except Exception as e:
        logger.exception(
            f"Failed to process {resource.kind} {resource.namespace}/{resource.name}: {e}"
        )


def autoscale_resources(
    api,
    kind,
    namespace: str,
    exclude_namespaces: FrozenSet[Pattern],
    exclude_names: FrozenSet[str],
    matching_labels: FrozenSet[Pattern],
    upscale_period: str,
    downscale_period: str,
    default_uptime: str,
    default_downtime: str,
    forced_uptime: bool,
    dry_run: bool,
    now: datetime.datetime,
    grace_period: int,
    downtime_replicas: int,
    deployment_time_annotation: Optional[str] = None,
    enable_events: bool = False,
):
    resources_by_namespace = collections.defaultdict(list)
    try:
        for resource in kind.objects(api, namespace=(namespace or pykube.all)):
            if resource.name in exclude_names:
                logger.debug(
                    f"{resource.kind} {resource.namespace}/{resource.name} was excluded (name matches exclusion list)"
                )
                continue
            if resource.kind == 'Job' and 'ownerReferences' in resource.metadata:
                logger.debug(
                    f"{resource.kind} {resource.namespace}/{resource.name} was excluded (Job with ownerReferences)"
                )
                continue
            resources_by_namespace[resource.namespace].append(resource)
    except requests.HTTPError as e:
        if e.response.status_code == 404:
            logger.debug(
                f"No {kind.endpoint} found in namespace {namespace} (404)"
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
        namespace_obj = Namespace.objects(api).get_by_name(current_namespace)

        excluded = ignore_resource(namespace_obj, now)

        default_uptime_for_namespace = namespace_obj.annotations.get(
            UPTIME_ANNOTATION, default_uptime
        )
        default_downtime_for_namespace = namespace_obj.annotations.get(
            DOWNTIME_ANNOTATION, default_downtime
        )
        default_downtime_replicas_for_namespace = get_annotation_value_as_int(
            namespace_obj, DOWNTIME_REPLICAS_ANNOTATION
        )
        if default_downtime_replicas_for_namespace is None:
            default_downtime_replicas_for_namespace = downtime_replicas

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
                dry_run,
                now,
                grace_period,
                default_downtime_replicas_for_namespace,
                namespace_excluded=excluded,
                deployment_time_annotation=deployment_time_annotation,
                enable_events=enable_events,
                matching_labels=matching_labels,
            )

def apply_kubedownscalerjobsconstraint_crd(excluded_names, matching_labels, api):
    kube_downscaler_jobs_constraint_crd = CustomResourceDefinition.objects(api).get_or_none(
        name="kubedownscalerjobsconstraint.constraints.gatekeeper.sh")
    obj = ConstraintTemplate.create_constraint_template_crd(excluded_names, matching_labels)
    if kube_downscaler_jobs_constraint_crd is not None:
        if obj == kube_downscaler_jobs_constraint_crd:
            logger.debug("kubedownscalerjobsconstraint.constraints.gatekeeper.sh CRD already present")
            return
        else:
            logger.debug("kubedownscalerjobsconstraint.constraints.gatekeeper.sh CRD updated")
            ConstraintTemplate(api, obj).update(obj)
    else:
        logger.debug("kubedownscalerjobsconstraint.constraints.gatekeeper.sh CRD created")
        ConstraintTemplate(api, obj).create()
        time.sleep(0.02)


def gatekeeper_constraint_template_crd_exist() -> bool:
    api = helper.get_kube_api()
    constraint_template_crd = CustomResourceDefinition.objects(api).get_or_none(
        name="constrainttemplates.templates.gatekeeper.sh")

    if constraint_template_crd is None:
        logging.error("constrainttemplates.templates.gatekeeper.sh CRD not found inside the cluster")
        return False
    else:
        logging.debug("constrainttemplates.templates.gatekeeper.sh CRD present inside the cluster")
        return True


def gatekeeper_healthy(api) -> bool:
    gatekeeper_audit = Deployment.objects(api).filter(namespace="gatekeeper-system").get_or_none(
        name="gatekeeper-audit")
    gatekeeper_controller_manager = Deployment.objects(api).filter(namespace="gatekeeper-system").get_or_none(
        name="gatekeeper-controller-manager")

    kubedownscalerjobsconstraint = CustomResourceDefinition.objects(api).get_or_none(
        name="kubedownscalerjobsconstraint.constraints.gatekeeper.sh")

    if gatekeeper_audit is None or gatekeeper_controller_manager is None:
        logging.debug("Health Check: gatekeeper deployments not found inside the default \"gatekeeper-system\" "
                      "namespace. While this is not a problem, downscaling jobs policy may not be enforced unless "
                      "gatekeeper is installed and healthy inside another namespace")
    else:
        if gatekeeper_audit.obj["spec"]["replicas"] > 0 and gatekeeper_controller_manager.obj["spec"]["replicas"] > 0:
            logging.debug("Health Check: gatekeeper deployments are healthy inside the \"gatekeeper-system\" namespace")
        else:
            logging.debug(
                "Health Check: gatekeeper deployments are not healthy inside the \"gatekeeper-system\" namespace "
                "downscaling jobs policy may not be enforced")

    if kubedownscalerjobsconstraint is None:
        logging.error("kubedownscalerjobsconstraint.constraints.gatekeeper.sh CRD not found inside the cluster")
        return False
    else:
        return True


def kyverno_healthy(api):
    kyverno_admission_controller = Deployment.objects(api).filter(namespace="kyverno").get_or_none(
        name="kyverno-admission-controller").obj
    kyverno_background_controller = Deployment.objects(api).filter(namespace="kyverno").get_or_none(
        name="kyverno-background-controller").obj
    kyverno_policy_crd = CustomResourceDefinition.objects(api).get_or_none(name="policies.kyverno.io")

    if kyverno_admission_controller is None or kyverno_background_controller is None:
        logging.debug("Health Check: kyverno deployments not found inside the default \"kyverno\" "
                      "namespace. While this is not a problem, downscaling jobs policy may not be enforced unless "
                      "kyverno is installed and healthy inside another namespace")
    else:
        if kyverno_admission_controller["spec"]["replicas"] > 0 and kyverno_background_controller["spec"][
            "replicas"] > 0:
            logging.debug("Health Check: kyverno deployments are healthy inside the \"kyverno\" namespace")
        else:
            logging.debug("Health Check: kyverno deployments are not healthy inside the \"kyverno\" namespace "
                          "downscaling jobs policy may not be enforced")

    if kyverno_policy_crd is None:
        logging.error("policies.kyverno.io CRD not found inside the cluster")
        return False
    else:
        return True
def autoscale_jobs(
        api,
        namespace: str,
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

        if admission_controller == "gatekeeper" and gatekeeper_constraint_template_crd_exist():
            apply_kubedownscalerjobsconstraint_crd(exclude_names, matching_labels, api)
            if admission_controller == "gatekeeper" and not gatekeeper_healthy(api):
                logging.error("unable to scale jobs, there was a problem applying kubedownscalerjobsconstraint crd or it was deleted"
                              " from the cluster. The crd will be automatically re-applied")
                return
        elif admission_controller == "gatekeeper" and not gatekeeper_constraint_template_crd_exist():
            logging.warning(
                "unable to scale jobs with gatekeeper until you install constrainttemplates.templates.gatekeeper.sh "
                "CRD")
            return

        if admission_controller == "kyverno" and not kyverno_healthy(api):
            logging.error("unable to scale jobs")
            return

        if namespace is not None:
            namespace_list = [namespace]
        else:
            namespace_list = list(Namespace.objects(api).iterator())

        excluded_jobs = []

        for name in exclude_names:
            excluded_jobs.append(name)

        for current_namespace in namespace_list:

            if any(
                    [pattern.fullmatch(current_namespace.name) for pattern in exclude_namespaces]
            ):
                logger.debug(
                    f"Namespace {current_namespace.name} was excluded from job scaling (exclusion list regex matches)"
                )
                continue

            logger.debug(
                f"Processing {current_namespace.name} for job scaling.."
            )

            excluded = ignore_resource(current_namespace, now)

            default_uptime_for_namespace = current_namespace.annotations.get(
                UPTIME_ANNOTATION, default_uptime
            )
            default_downtime_for_namespace = current_namespace.annotations.get(
                DOWNTIME_ANNOTATION, default_downtime
            )

            upscale_period_for_namespace = current_namespace.annotations.get(
                UPSCALE_PERIOD_ANNOTATION, upscale_period
            )
            downscale_period_for_namespace = current_namespace.annotations.get(
                DOWNSCALE_PERIOD_ANNOTATION, downscale_period
            )
            forced_uptime_value_for_namespace = str(
                current_namespace.annotations.get(FORCE_UPTIME_ANNOTATION, forced_uptime)
            )
            forced_downtime_value_for_namespace = str(
                current_namespace.annotations.get(FORCE_DOWNTIME_ANNOTATION, False)
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
            logger.warning("admission controller arg was not specified, unable to scale jobs")
        else:
            logger.warning(
                "admission controller arg is not written correctly or not supported"
            )

def scale(
    namespace: str,
    upscale_period: str,
    downscale_period: str,
    default_uptime: str,
    default_downtime: str,
    include_resources: FrozenSet[str],
    exclude_namespaces: FrozenSet[Pattern],
    exclude_deployments: FrozenSet[str],
    dry_run: bool,
    grace_period: int,
    admission_controller: str,
    downtime_replicas: int = 0,
    deployment_time_annotation: Optional[str] = None,
    enable_events: bool = False,
    matching_labels: FrozenSet[Pattern] = frozenset(),
):
    api = helper.get_kube_api()

    now = datetime.datetime.now(datetime.timezone.utc)
    forced_uptime = pods_force_uptime(api, namespace)

    for clazz in RESOURCE_CLASSES:
        plural = clazz.endpoint
        if plural in include_resources:
            if scale_jobs_without_admission_controller(plural, admission_controller) or plural != "jobs":
                autoscale_resources(
                    api,
                    clazz,
                    namespace,
                    exclude_namespaces,
                    exclude_deployments,
                    matching_labels,
                    upscale_period,
                    downscale_period,
                    default_uptime,
                    default_downtime,
                    forced_uptime,
                    dry_run,
                    now,
                    grace_period,
                    downtime_replicas,
                    deployment_time_annotation,
                    enable_events,
                )
            else:
                autoscale_jobs(
                    api,
                    namespace,
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
