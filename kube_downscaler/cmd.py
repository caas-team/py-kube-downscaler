import argparse
import os

VALID_RESOURCES = frozenset(
    [
        "deployments",
        "statefulsets",
        "stacks",
        "cronjobs",
        "horizontalpodautoscalers",
        "rollouts",
        "scaledobjects",
        "jobs",
        "daemonsets",
        "poddisruptionbudgets",
        "autoscalingrunnersets",
    ]
)


def check_include_resources(value):
    resources = frozenset(value.split(","))
    if not resources <= VALID_RESOURCES:
        raise argparse.ArgumentTypeError(
            f"--include-resources argument should contain a subset of [{', '.join(sorted(VALID_RESOURCES))}]"
        )
    return value


def get_parser():
    parser = argparse.ArgumentParser()
    upscale_group = parser.add_mutually_exclusive_group(required=False)
    downscalescale_group = parser.add_mutually_exclusive_group(required=False)
    parser.add_argument(
        "--dry-run",
        help="Dry run mode: do not change anything, just print what would be done",
        action="store_true",
    )
    parser.add_argument(
        "--debug", "-d", help="Debug mode: print more information", action="store_true"
    )
    parser.add_argument(
        "--once", help="Run loop only once and exit", action="store_true"
    )
    parser.add_argument(
        "--interval", type=int, help="Loop interval (default: 30s)", default=30
    )
    parser.add_argument(
        "--upscale-target-only",
        help="Upscale only resource in target when waking up namespaces",
        action="store_true",
    )
    parser.add_argument(
        "--namespace", help="Namespace", default=os.getenv("NAMESPACE", "")
    )
    parser.add_argument(
        "--include-resources",
        type=check_include_resources,
        default=os.getenv("INCLUDE_RESOURCES", "deployments"),
        help=f"Downscale resources of this kind as comma separated list. [{', '.join(sorted(VALID_RESOURCES))}] (default: deployments)",
    )
    parser.add_argument(
        "--grace-period",
        type=int,
        help="Grace period in seconds for deployments before scaling down (default: 15min)",
        default=os.getenv("GRACE_PERIOD", 900),
    )
    parser.add_argument(
        "--api-server-timeout",
        type=int,
        help="Timeout to be used when kubedownscaler performs call to the Kubernetes API Server (default: 10s)",
        default=os.getenv("API_SERVER_TIMEOUT", 10),
    )
    parser.add_argument(
        "--max-retries-on-conflict",
        type=int,
        help="Maximum number of retries for handling concurrent update conflicts (default: 0)",
        default=os.getenv("MAX_RETRIES_ON_CONFLICT", 0),
    )
    upscale_group.add_argument(
        "--upscale-period",
        help="Default time period to scale up once (default: never)",
        default=os.getenv("UPSCALE_PERIOD", "never"),
    )
    upscale_group.add_argument(
        "--default-uptime",
        help="Default time range to scale up for (default: always)",
        default=os.getenv("DEFAULT_UPTIME", "always"),
    )
    downscalescale_group.add_argument(
        "--downscale-period",
        help="Default time period to scale down once (default: never)",
        default=os.getenv("DOWNSCALE_PERIOD", "never"),
    )
    downscalescale_group.add_argument(
        "--default-downtime",
        help="Default time range to scale down for (default: never)",
        default=os.getenv("DEFAULT_DOWNTIME", "never"),
    )
    parser.add_argument(
        "--exclude-namespaces",
        help="Exclude namespaces from downscaling, comma-separated list of regex patterns (default: kube-system)",
        default=os.getenv("EXCLUDE_NAMESPACES", "kube-system"),
    )
    parser.add_argument(
        "--exclude-deployments",
        help="Exclude specific deployments from downscaling. Despite its name, this option will match the name of any included resource type (Deployment, StatefulSet, CronJob, ..). (default: py-kube-downscaler,kube-downscaler,downscaler)",
        default=os.getenv(
            "EXCLUDE_DEPLOYMENTS", "py-kube-downscaler,kube-downscaler,downscaler"
        ),
    )
    parser.add_argument(
        "--downtime-replicas",
        type=str,
        help="Default value used when downscaling (default: '0')",
        default=os.getenv("DOWNTIME_REPLICAS", "0"),
    )
    parser.add_argument(
        "--deployment-time-annotation",
        help="Annotation that contains a resource's last deployment time, overrides creationTime. Use in combination with --grace-period.",
    )
    parser.add_argument(
        "--enable-events",
        help="Emit Kubernetes events for scale up/down",
        action="store_true",
    )
    parser.add_argument(
        "--matching-labels",
        default=os.getenv("MATCHING_LABELS", ""),
        help="Apply downscaling to resources with the supplied labels. This is a comma-separated list of regex patterns. This is optional, downscaling will be applied to all resources by default.",
    )
    parser.add_argument(
        "--admission-controller",
        default=os.getenv("ADMISSION_CONTROLLER", ""),
        help="Apply downscaling to jobs using the supplied admission controller. Jobs should be included inside --include-resources if you want to use this parameter. kyverno and gatekeeper are supported.",
    )
    return parser
