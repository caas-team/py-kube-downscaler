# Python Kubernetes Downscaler

<a href="/../../releases/" title="GitHub Release"><img alt="GitHub Release" src="https://img.shields.io/github/v/release/caas-team/py-kube-downscaler?style=flat"></a>
<a href="./LICENSE" title="GitHub License"><img alt="GitHub License" src="https://img.shields.io/github/license/caas-team/py-kube-downscaler?style=flat"></a>
<a href="/../../issues/" title="GitHub Issues"><img alt="GitHub Issues" src="https://img.shields.io/github/issues/caas-team/py-kube-downscaler"></a>
<a href="https://inviter.co/kube-downscaler" title="Slack Workspace"><img alt="Slack Workspace" src="https://img.shields.io/badge/slack-kube--downscaler-dark_green?style=flat&logo=slack"></a>

This is a fork of the no longer maintained [hjacobs/kube-downscaler](https://codeberg.org/hjacobs/kube-downscaler).

> [!IMPORTANT]  
> The **py-kube-downscaler** is in **maintenance-only mode**.  
> If you're still looking to get feature updates, please [migrate to the successor](https://caas-team.github.io/GoKubeDownscaler/guides/migrating), the [**GoKubeDownscaler**](https://github.com/caas-team/GoKubeDownscaler), which is faster, more efficient, and includes additional and comfort features.

Scale down / "pause" Kubernetes workload (`Deployments`, `StatefulSets`,
`HorizontalPodAutoscalers`, `DaemonSets`, `CronJobs`, `Jobs`, `PodDisruptionBudgets`, `Argo Rollouts` and `Keda ScaledObjects` too !) during non-work hours.

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

**Table of Contents** _generated with [DocToc](https://github.com/thlorenz/doctoc)_

- [Python Kubernetes Downscaler](#python-kubernetes-downscaler)
  - [Concepts](#concepts)
    - [Algorithm](#algorithm)
    - [Minimum replicas](#minimum-replicas)
    - [Specific workload](#specific-workload)
    - [Example use cases](#example-use-cases)
  - [Usage](#usage)
    - [Helm Chart](#helm-chart)
    - [Example configuration](#example-configuration)
    - [Notes](#notes)
  - [Installation](#installation)
    - [Cluster Wide Access Installation](#cluster-wide-access-installation)
    - [Limited Access Installation](#limited-access-installation)
  - [Configuration](#configuration)
    - [Uptime / downtime spec](#uptime--downtime-spec)
    - [Alternative Logic, Based on Periods](#alternative-logic-based-on-periods)
    - [Command Line Options](#command-line-options)
    - [Constrained Mode (Limited Access Mode)](#constrained-mode-limited-access-mode)
    - [Scaling Jobs: Overview](#scaling-jobs-overview)
    - [Scaling Jobs Natively](#scaling-jobs-natively)
    - [Scaling Jobs With Admission Controller](#scaling-jobs-with-admission-controller)
    - [Scaling DaemonSets](#scaling-daemonsets)
    - [Scaling ScaledObjects](#scaling-scaledobjects)
    - [Matching Labels Argument](#matching-labels-argument)
    - [Namespace Defaults](#namespace-defaults)
  - [Verifying Cosign Signature](#verifying-cosign-signature)
  - [Migrate From Codeberg](#migrate-from-codeberg)
    - [Migrate From Codeberg - Cluster Wide Installation](#migrate-from-codeberg---cluster-wide-installation)
    - [Migrate From Codeberg - Limited Access Installation](#migrate-from-codeberg---limited-access-installation)
  - [Contributing](#contributing)
  - [License](#license)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Concepts

> :memo: `Deployments` are interchangeable by any kind of _supported workload_ for this whole guide unless explicitly stated otherwise.
>
> The complete list of supported workload is defined [here](./kube_downscaler/scaler.py#9-14).

### Algorithm

`py-kube-downscaler` will scale down the deployment\'s replicas if all of the following
conditions are met:

- **current time** is not part of the \"uptime\" schedule or is part of the \"downtime\" schedule.

  If true, the schedules are evaluated in the following order:

  - `downscaler/downscale-period` or `downscaler/downtime`
    annotation on the workload definition
  - `downscaler/upscale-period` or `downscaler/uptime`
    annotation on the workload definition
  - `downscaler/downscale-period` or `downscaler/downtime`
    annotation on the workload\'s namespace
  - `downscaler/upscale-period` or `downscaler/uptime`
    annotation on the workload\'s namespace
  - `--upscale-period` or `--default-uptime` CLI argument
  - `--downscale-period` or `--default-downtime` CLI argument
  - `UPSCALE_PERIOD` or `DEFAULT_UPTIME` environment variable
  - `DOWNSCALE_PERIOD` or `DEFAULT_DOWNTIME` environment
    variable

- The workload\'s **namespace** is not part of the exclusion list:

  - If you provide an exclusion list, it will be used in place
    of the default (which includes only `kube-system`).

- The workload\'s label does not match the labels list.

- The **workload\'s name** is not part of the exclusion list

- The workload is not marked for exclusion (annotation
  `downscaler/exclude: "true"` or
  `downscaler/exclude-until: "2024-04-05"`)

- There are no active pods that force the whole cluster into uptime
  (annotation `downscaler/force-uptime: "true"`)

### Minimum replicas

The deployment, by default, **will be scaled down to zero replicas**. This can
be configured with a deployment or its namespace\'s annotation of `downscaler/downtime-replicas`
or via CLI with `--downtime-replicas`.

Ex: `downscaler/downtime-replicas: "1"`

### Specific workload

In case of `HorizontalPodAutoscalers`, the `minReplicas` field cannot be set to zero and thus
`downscaler/downtime-replicas` should be at least `1`.

-> See later in [#Usage notes](#notes)

Regarding `CronJobs`, their state will be defined to `suspend: true` as you might expect.

### Example use cases

- Deploy the downscaler to a test (non-prod) cluster with a default
  uptime or downtime time range to scale down all deployments during
  the night and weekend.
- Deploy the downscaler to a production cluster without any default
  uptime/downtime setting and scale down specific deployments by
  setting the `downscaler/uptime` (or `downscaler/downtime`)
  annotation. This might be useful for internal tooling frontends
  which are only needed during work time.

You need to combine the downscaler with an elastic cluster autoscaler to
actually **save cloud costs**. The [official cluster
autoscaler](https://github.com/kubernetes/autoscaler/tree/master/cluster-autoscaler)
and the
[kube-aws-autoscaler](https://github.com/hjacobs/kube-aws-autoscaler)
were tested to work fine with the downscaler.

## Usage

### Helm Chart

For detailed information on deploying the `py-kube-downscaler` using our Helm chart, please refer to the [Helm Chart README](./chart/README.md#Deploy-py-kube-downscaler-using-Helm-chart) in the chart directory.

### Example configuration

The example configuration uses the `--dry-run` as a safety flag to
prevent downscaling \-\-- remove it to enable the downscaler, e.g. by
editing the deployment:

```bash
$ kubectl edit deploy py-kube-downscaler
```

The example deployment manifests come with a configured uptime
(`deploy/config.yaml` sets it to \"Mon-Fri 07:30-20:30 CET\"), you can
overwrite this per namespace or deployment, e.g.:

```bash
$ kubectl run nginx --image=nginx
$ kubectl annotate deploy nginx 'downscaler/uptime=Mon-Fri 09:00-17:00 America/Buenos_Aires'
```

### Notes

Note that the _default grace period_ of 15 minutes applies to the new
nginx deployment, i.e.

- if the current time is not within `Mon-Fri 9-17 (Buenos Aires timezone)`,
  it will downscale not immediately, but after 15 minutes. The downscaler
  will eventually log something like:

```
INFO: Scaling down Deployment default/nginx from 1 to 0 replicas (uptime: Mon-Fri 09:00-17:00 America/Buenos_Aires, downtime: never)
```

Note that in cases where a `HorizontalPodAutoscaler` (HPA) is used along
with Deployments, consider the following:

- If downscale to 0 replicas is desired, the annotation should be
  applied on the `Deployment`. This is a special case, since
  `minReplicas` of 0 on HPA is not allowed. Setting Deployment
  replicas to 0 essentially disables the HPA. In such a case, the HPA
  will emit events like `failed to get memory utilization: unable to
get metrics for resource memory: no metrics returned from resource
metrics API` as there is no Pod to retrieve metrics from.
- If downscale greater than 0 is desired, the annotation should be
  applied on the HPA. This allows for dynamic scaling of the Pods even
  during downtime based upon the external traffic as well as maintain
  a lower `minReplicas` during downtime if there is no/low traffic. **If
  the Deployment is annotated instead of the HPA, it leads to a race
  condition** where `py-kube-downscaler` scales down the Deployment and HPA
  upscales it as its `minReplicas` is higher.

To enable Downscaler on HPA with `--downtime-replicas=1`,
ensure to add the following annotations to Deployment and HPA.

```bash
$ kubectl annotate deploy nginx 'downscaler/exclude=true'
$ kubectl annotate hpa nginx 'downscaler/downtime-replicas=1'
$ kubectl annotate hpa nginx 'downscaler/uptime=Mon-Fri 09:00-17:00 America/Buenos_Aires'
```

## Installation

KubeDownscaler offers two installation methods.

- **Cluster Wide Access**: This method is dedicated for users who have total access to the Cluster and aspire to adopt the
  tool throughout the cluster
- **Limited Access**: This method is dedicated to users who only have access to a limited number of namespaces and can
  adopt the tool only within them

### Cluster Wide Access Installation

**RBAC-Prerequisite**: This installation mode requires permission to deploy Service Account, ClusterRole, ClusterRoleBinding, CRDs

The basic Cluster Wide installation is very simple

```bash
$ helm install py-kube-downscaler oci://ghcr.io/caas-team/charts/py-kube-downscaler
```

This command will deploy:

- **Deployment**: main deployment
- **ConfigMap**: used to supply parameters to the deployment
- **ServiceAccount**: represents the Cluster Idenity of the KubeDownscaler
- **ClusterRole**: needed to access all the resources that can be modified by the KubeDownscaler
- **ClusterRoleBinding**: links the ServiceAccount used by KubeDownscaler to the ClusterRole

It is possible to further customize it by changing the parameters present in the values.yaml file of the Chart

### Limited Access Installation

**RBAC-Prerequisite**: This installation mode requires permission to deploy Service Account, Role and RoleBinding

The Limited Access installation requires the user to fill the following parameters inside values.yaml

- **constrainedDownscaler**: true (mandatory)
- **constrainedNamespaces**: [namespace1,namespace2,namespace3,...] (list of namespaces - mandatory)

It is also recommended to explicitly set the namespace where KubeDownscaler will be installed

```bash
$ helm install py-kube-downscaler oci://ghcr.io/caas-team/charts/py-kube-downscaler --namespace my-release-namespace --set constrainedDownscaler=true --set "constrainedNamespaces={namespace1,namespace2,namespace3}"
```

This command will deploy:

- **Deployment**: main deployment
- **ConfigMap**: used to supply parameters to the deployment
- **ServiceAccount**: represents the Cluster Identity of the KubeDownscaler

For each namespace inside constrainedNamespaces, the chart will deploy

- **Role**: needed to access all the resources that can be modified by the KubeDownscaler (inside that namespace)
- **RoleBinding**: links the ServiceAccount used by KubeDownscaler to the Role inside that namespace

If RBAC permissions are misconfigured and the KubeDownscaler is unable to access resources in one of the specified namespaces,
a warning message will appear in the logs indicating a `403 Error`

## Configuration

### Uptime / downtime spec

The downscaler is configured via command line args, environment
variables and/or Kubernetes annotations.

Time definitions (e.g. `DEFAULT_UPTIME`) accept a comma separated list
of specifications, e.g. the following configuration would downscale all
deployments for non-work hours:

```bash
DEFAULT_UPTIME="Mon-Fri 07:30-20:30 Europe/Berlin"
```

To only downscale during the weekend and Friday after 20:00:

```bash
DEFAULT_DOWNTIME="Sat-Sun 00:00-24:00 CET,Fri-Fri 20:00-24:00 CET'
```

Each time specification can be in one of two formats:

- Recurring specifications have the format
  `<WEEKDAY-FROM>-<WEEKDAY-TO-INCLUSIVE> <HH>:<MM>-<HH>:<MM> <TIMEZONE>`.
  The timezone value can be any [Olson
  timezone](https://en.wikipedia.org/wiki/Tz_database), e.g.
  \"US/Eastern\", \"PST\" or \"UTC\".
- Absolute specifications have the format `<TIME_FROM>-<TIME_TO>`
  where each `<TIME>` is an ISO 8601 date and time of the format
  `<YYYY>-<MM>-<DD>T<HH>:<MM>:<SS>[+-]<TZHH>:<TZMM>`.

If you are using the first format (recurring specifications) it is important
to note that the downscaler can only interpret configurations within
a single day and cannot process intervals that stretch across two different days.
As a result, overlapping time intervals are not supported.

In the expression `<WEEKDAY-FROM>-<WEEKDAY-TO-INCLUSIVE> <HH>:<MM>-<HH>:<MM> <TIMEZONE>`
the time range `<HH>:<MM>-<HH>:<MM>` should always have the end time later
than the start time (in 24-hour format)

If you want to schedule downtime from 23:30 to 09:30 the following day,
a configuration like this would be incorrect:

`DEFAULT_DOWNTIME="Mon-Fri 23:30-09:30 Europe/Berlin"`

The correct configuration would be:

`DEFAULT_DOWNTIME="Mon-Fri 23:30-24:00 Europe/Berlin,Mon-Fri 00:00-09:30 Europe/Berlin"`

### Alternative Logic, Based on Periods

Instead of strict uptimes or downtimes, you can chose time periods for
upscaling or downscaling. The time definitions are the same. In this
case, the upscale or downscale happens only on time periods, rest of
times will be ignored.

If upscale or downscale periods are configured, uptime and downtime will
be ignored. This means that some options are mutually exclusive, e.g.
you can either use `--downscale-period` or `--default-downtime`, but not
both.

This definition will downscale your cluster between 19:00 and 20:00. If
you upscale your cluster manually, it won\'t be scaled down until next
day 19:00-20:00.

```bash
DOWNSCALE_PERIOD="Mon-Sun 19:00-20:00 Europe/Berlin"
```

### Command Line Options

Available command line options:

`--dry-run`

: Dry run mode: do not change anything, just print what would be done

`--debug`

: Debug mode: print more information

`--once`

: Run loop only once and exit

`--interval`

: Loop interval (default: 60s)

`--namespace`

: Restrict the downscaler to work only in some namespaces (default:
all namespaces). This is mainly useful for deployment scenarios
where the deployer of py-kube-downscaler only has access to some
namespaces (instead of cluster wide access). If used simultaneously with
`--exclude-namespaces`, `--namespace` will take precedence overriding
its value. This argument takes a comma separated list of namespaces
(example: --namespace=default,test-namespace1,test-namespace2)

> [!IMPORTANT]
> It's strongly not advised to use this argument in a Cluster
> Wide Access installation, see the [Constrained Mode](#constrained-mode-limited-access-mode) section

`--include-resources`

: Downscale resources of this kind as comma separated list. Available resources are:
`[deployments, statefulsets, stacks, horizontalpodautoscalers, cronjobs, daemonsets, poddisruptionbudgets, rollouts, scaledobjects, jobs]`
(default: deployments)

`--grace-period`

: Grace period in seconds for new deployments before scaling them down
(default: 15min). The grace period counts from time of creation of
the deployment, i.e. updated deployments will immediately be scaled
down regardless of the grace period. If the `downscaler/grace-period`
annotation is present in a resource and its value is shorter than
the global grace period, the annotation's value will override the
global grace period for that specific resource.

`--upscale-period`

: Alternative logic to scale up only in given period of time (default:
never), can also be configured via environment variable
`UPSCALE_PERIOD` or via the annotation `downscaler/upscale-period`
on each deployment

`--downscale-period`

: Alternative logic to scale down only in given period of time
(default: never), can also be configured via environment variable
`DOWNSCALE_PERIOD` or via the annotation
`downscaler/downscale-period` on each deployment

`--default-uptime`

: Default time range to scale up for (default: always), can also be
configured via environment variable `DEFAULT_UPTIME` or via the
annotation `downscaler/uptime` on each deployment

`--default-downtime`

: Default time range to scale down for (default: never), can also be
configured via environment variable `DEFAULT_DOWNTIME` or via the
annotation `downscaler/downtime` on each deployment

`--upscale-target-only`

: When this optional argument is used, only the namespaces currently
targeted by the downscaler will be upscaled during wake-up times.
For instance, if your downscaler initially manages namespaces
A, B, and C, but is later reconfigured to target only namespaces
B and C, namespace A will remain downscaled if it was downscaled
at the time of reconfiguration. If the parameter is not used,
all previously downscaled namespaces may be upscaled, even if
they are no longer targeted by the downscaler.

`--exclude-namespaces`

: Exclude namespaces from downscaling (list of regex patterns,
default: kube-system), can also be configured via environment
variable `EXCLUDE_NAMESPACES`. If used simultaneously with
`--exclude-namespaces`, `--namespace` will take precedence
overriding its value.

`--exclude-deployments`

: Exclude specific deployments/statefulsets/cronjobs from downscaling
(default: py-kube-downscaler, downscaler), can also be configured via
environment variable `EXCLUDE_DEPLOYMENTS`. Despite its name, this
option will match the name of any included resource type
(Deployment, StatefulSet, CronJob, ..).

`--downtime-replicas`

: Default value of replicas to downscale to, the annotation
`downscaler/downtime-replicas` takes precedence over this value.

`--deployment-time-annotation`

: Optional: name of the annotation that would be used instead of the
creation timestamp of the resource. This option should be used if
you want the resources to be kept scaled up during a grace period
(`--grace-period`) after a deployment. The format of the
annotation\'s timestamp value must be exactly the same as for
Kubernetes\' `creationTimestamp`: `%Y-%m-%dT%H:%M:%SZ`. Recommended:
set this annotation by your deployment tooling automatically.

`--matching-labels`

: Optional: list of workload\'s labels which are covered by the py-kube-downscaler
scope. All workloads whose labels don't match any in the list are ignored.
For backwards compatibility, if this argument is not specified,
py-kube-downscaler will apply to all resources.

`--admission-controller`

: Optional: admission controller used by the kube-downscaler to downscale and upscale
jobs. This argument won't take effect if used in conjunction with `--namespace` argument.
Supported Admission Controllers are
\[gatekeeper, kyverno\*\]

> [!IMPORTANT]
> Make sure to read the [Scaling Jobs With Admission Controller](#scaling-jobs-with-admission-controller) section
> to understand how to use the `--admission-controller` feature correctly

`--api-server-timeout`

: Optional: This is an advanced option that allows setting a timeout duration for all
calls made by Kube Downscaler to the Kubernetes API Server. It can only take integer values
(default: 10). This setting should only be added to Kube Downscaler arguments if timeout
issues are observed in the logs.

`--max-retries-on-conflict`

: Optional: Specifies the maximum number of retries KubeDownscaler should perform
when encountering a conflict error (HTTP 409). These errors occur when one of the
resources, just before being processed by Kube Downscaler, is modified by another entity,
such as an HPA, CI/CD pipeline, or manual intervention. If enabled, Kube Downscaler will
retry the update immediately, without waiting for the next iteration (default: 0). This
argument is strongly recommended when using the `--once` argument to process large clusters

### Constrained Mode (Limited Access Mode)

The Constrained Mode (also known as Limited Access Mode) is designed for users who do not have full cluster access.
It is automatically activated when the `--namespace` argument is specified.
This mode utilizes a different set of API calls optimized for environments where users cannot deploy ClusterRole and ClusterRoleBinding.
Additionally, this mode disables the ability to scale Jobs via Admission Controllers since the
"[Scaling Jobs With Admission Controllers](#scaling-jobs-with-admission-controller)" feature requires Full
Cluster Access to operate.

If you are installing KubeDownscaler with full cluster access,
it is strongly recommended to use the `--exclude-namespaces` parameter instead of `--namespace`. Using `--namespace`
in a cluster wide access installation will make API calls less efficient and
will disable the ability to scale Jobs with Admission Controllers for the reason specified above.

### Scaling Jobs: Overview

Kube Downscaler offers two possibilities for downscaling Jobs:

1. Downscaling Jobs Natively: Kube Downscaler will downscale Jobs by modifying the spec.suspend parameter
   within the job's yaml file. The spec.suspend parameter will be set to True and the pods created by the Job
   will be automatically deleted.

2. Downscaling Jobs With Admission Controllers: Kube Downscaler will block the creation of all new Jobs using
   Admission Policies created with an Admission Controller (Kyverno or Gatekeeper, depending on the user's choice).

In both cases, all Jobs created by CronJob will not be modified unless the user specifies via the
`--include-resources` argument that they want to turn off both Jobs and CronJobs

**How To Choose The Correct Mode:**

1. The first mode is recommended when the Jobs created within the Cluster are few and sporadic

2. The second mode is recommended when there are many Jobs created within the Cluster and they are created at very frequent intervals.

it's important to note the following:

The second mode is specifically designed to avoid frequent node provisioning. This is particularly relevant when KubeDownscaler
might turn off jobs shortly after they've triggered node provisioning. If jobs trigger node provisioning but are then
scaled down or stopped by KubeDownscaler within 30 to 60 seconds, the Cluster Autoscaler is basically doing an unnecessary
provisioning action because the new nodes will be scaled down shortly after as well. Frequently provisioning nodes only to
have them become unnecessary shortly thereafter is an operation that should be minimized, as it is inefficient.

### Scaling Jobs Natively

To scale down jobs natively, you only need to specify `jobs` inside the `--include-resource` argument of the Deployment

### Scaling Jobs With Admission Controller

Before scaling jobs with an Admission Controller make sure the Admission Controller of your choice is correctly installed inside the
cluster.
At startup, Kube-Downscaler will always perform some health checks for the Admission Controller of your choice that are
displayed inside logs when the argument `--debug` arg is present inside the main Deployment.

**<u>Important</u>: In order to use this feature you will need to exclude Kyverno or Gatekeeper resources from downscaling otherwise
the admission controller pods won't be able to block jobs.** You can use `EXCLUDE_NAMESPACES` environment variable or `--exclude-namespaces`
arg to exclude `"kyverno"` or `"gatekeeper-system"` namespaces.
Alternatively `EXCLUDE_DEPLOYMENTS` environment variable
or `--exclude-deployments` arg to exclude only certain resources inside `"kyverno"` or `"gatekeeper-system"` namespaces

**<u>Important</u>**: `--admission-controller` argument won't take effect if used in conjunction with --namespace argument.
if you specified `jobs` inside the `--include-resources` argument KubeDownscaler will
still [downscale jobs natively](#scaling-jobs-natively).
Please read the [Constrained Mode](#constrained-mode-limited-access-mode) section to understand why

The workflow for blocking jobs is different if you use Gatekeeper or Kyverno, both are described below

**Blocking Jobs: Gatekeeper Workflow**

1. Kube-Downscaler will install a new Custom Resource Definition
   called `kubedownscalerjobsconstraint`.
2. Kube-Downscaler will create a Constraint called "KubeDownscalerJobsConstraint" for each namespace that is not excluded

**Blocking Jobs: Kyverno Workflow**

1. Kube-Downscaler will create a Policy for each namespace that is not excluded

All the statements below are valid for both Kyverno and Gatekeeper, unless specified otherwise

**<u>Important</u>:** Jobs started from CronJobs are excluded by default unless you have included `cronjobs` inside `--include-resources` argument

**Annotations:** both the `downscaler/exclude` and `downscaler/exclude-until` annotations are fully supported
inside jobs to exclude them from downscaling. However, when using `downscaler/exclude-until`, the time <u>**must**</u> be specified in the RFC format `YYYY-MM-DDT00:00:00Z`
otherwise the exclusion won't work.
Please check the example below

```yaml {.sourceCode .yaml}
apiVersion: batch/v1
kind: Job
metadata:
  namespace: default
  name: testjob
  annotations:
    downscaler/exclude-until: "2024-01-31T00:00:00Z"
spec:
  template:
    spec:
      containers:
        - image: nginx
          name: testjob
      restartPolicy: Never
```

**Arguments and Env:** you can also use `EXCLUDE_DEPLOYMENTS` environment variable or the argument `--exclude-deployments`
to exclude jobs. As described above, despite their names, these variables work for any type of workload

**<u>Important</u>:**
`downscaler/downscale-period`, `downscaler/downtime`, `downscaler/upscale-period`, `downscaler/uptime`
annotations are not supported if specified directly inside the Job definition due to limitations
on computing days of the week inside the policies. However you can still use
these annotations at Namespace level to downscale/upscale Jobs

**<u>Important</u>:**
global `--grace-period` is not supported for this feature at the moment, however `downscaler/downscale-period` annotation is
supported at namespace level when used to scale down jobs with Admission Controllers

**<u>Important</u>:**

**Deleting Policies:** if for some reason you want to delete all resources blocking jobs, you can use these commands:

Gatekeeper

```bash
$ kubectl delete constraints -A -l origin=kube-downscaler
```

Kyverno

```bash
$ kubectl delete policies -A -l origin=kube-downscaler
```

### Scaling DaemonSets

The feature to scale DaemonSets can be very useful for reducing the base occupancy of a node. If enabled, the DaemonSets downscaling algorithm works like this:

1. Downtime Hours: Kube Downscaler will add to each targeted DaemonSet a Node Selector that cannot be satisfied `kube-downscaler-non-existent=true`
2. Uptime Hours: Kube Downscaler will remove the `kube-downscaler-non-existent=true` Node Selector from each targeted DaemonSet

### Scaling ScaledObjects

The ability to downscale ScaledObjects is very useful for workloads that use Keda to support
a wider range of horizontal scaling metrics compared to the native Horizontal Pod Autoscaler (HPA).
Keda provides a built-in way to disable ScaledObjects when they are not needed. This can be achieved by using
the annotation `"autoscaling.keda.sh/paused-replicas"`.

The KubeDownscaler algorithm will apply the annotation `"autoscaling.keda.sh/paused-replicas" `
during downtime periods, setting its value to what the user specifies through the KubeDownscaler argument `--downtime-replicas`
or the workload annotation `"downscaler/downtime-replicas"`. During uptime, KubeDownscaler will remove the
`"autoscaling.keda.sh/paused-replicas"` annotation, allowing the ScaledObject to operate as originally configured.

**Important**: When using the `"downscaler/downtime-replicas"` annotation at the workload level, it is crucial that
this annotation is included in both the ScaledObject and the corresponding Deployment or StatefulSet that it controls
and the values of the annotation must match in both locations. Alternatively, it is possible to exclude the Deployment
or StatefulSet from scaling by using the annotation `"downscaler/exclude"`, while keeping downscaling active only
on the ScaledObject.

**Important**: KubeDownscaler has an automatic mechanism that detects if the `"autoscaling.keda.sh/paused-replicas" `
annotation is already present on the ScaledObject. If that is the case, KubeDownscaler will overwrite it
with the target value specified for downtime and, during uptime, will restore the original value.

**Technical Detail**: During downscaling, KubeDownscaler will set the annotation `"downscaler/original-replicas"` to -1, this value acts as a placeholder to indicate
that the ScaledObject was active during uptime.

### Matching Labels Argument

Labels, in Kubernetes, are key-value pairs that can be used to identify and group resources.

You can use the `--matching-labels` argument to include only certain resources in the namespaces
that are targeted by the Kube Downscaler. inside this argument you can specify:

- labels written in this format [key=value]
- regular expressions that target this format [key=value].

Each entry must be separated by a comma (`,`). If multiple entries are specified, the Kube Downscaler evaluates them as an OR condition

To make it more clear, given the following resource

```yaml {.sourceCode .yaml}
kind: Deployment
metadata:
  labels:
    app: nginx
    type: example
  name: nginx
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
        - image: nginx
          name: nginx
```

Kube-Downscaler will evaluate the input of the `--matching-labels` argument against _app=nginx_
and _type=example_. If at least one of the two key-value pairs matches the resource will be downscaled

Example of valid inputs are:

`--matching-labels=hello=world`: if the resource has a label "hello" equals to "world" it will be downscaled

`--matching-labels=hello=world,version=2.0`: if the resource has a label "hello" equals to "world"
or a label "version" equal to "2.0" it will be downscaled

`--matching-labels=^it-plt.*`: if the resource has a label that starts with "it-plt" it will be downscaled

`--matching-labels=^it-plt.*,not-critical=true`: if the resource has a label that starts with "it-plt" or a label
"not-critical" equals to "true" it will be downscaled

### Namespace Defaults

`DEFAULT_UPTIME`, `DEFAULT_DOWNTIME`, `FORCE_UPTIME` and exclusion can
also be configured using Namespace annotations. **Where configured these
values supersede the other global default values**.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: foo
  labels:
    name: foo
  annotations:
    downscaler/uptime: Mon-Sun 07:30-18:00 CET
```

The following annotations are supported on the Namespace level:

- `downscaler/upscale-period`
- `downscaler/downscale-period`
- `downscaler/uptime`: set \"uptime\" for all resources in this
  namespace
- `downscaler/downtime`: set \"downtime\" for all resources in this
  namespace
- `downscaler/force-downtime`: force scaling down all resources in this
  namespace - can be `true`/`false` or a period
- `downscaler/force-uptime`: force scaling up all resources in this
  namespace - can be `true`/`false` or a period
- `downscaler/exclude`: set to `true` to exclude all resources in the
  namespace
- `downscaler/exclude-until`: temporarily exclude all resources in the
  namespace until the given timestamp
- `downscaler/downtime-replicas`: overwrite the default target
  replicas to scale down to (default: zero)

## Verifying Cosign Signature

Public Key:

```text title="cosign.pub"
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgei36FSIhT8a9lOHs1Sem5KvmrT+
Xi2EcyjLvaJzqu5n0TiygGeO4ZcU30A1PQv6xoI0xBxpyZAw7XeqzrRDOQ==
-----END PUBLIC KEY-----
```

```bash
cosign verify --key cosign.pub --insecure-ignore-tlog ghcr.io/caas-team/py-kube-downscaler:24.12.0
```

## Migrate From Codeberg

For all users who come from the Codeberg repository (no longer maintained by the original author)
it is possible to migrate to this new version of the kube-downscaler by installing the Helm chart in these ways that will
preserve the old nomenclature already present inside your cluster

### Migrate From Codeberg - Cluster Wide Installation

Read [Installation](#installation) section to understand what is meant for **Cluster Wide Installation**

```bash
$ helm install kube-downscaler oci://ghcr.io/caas-team/charts/py-kube-downscaler --set nameOverride=kube-downscaler --set configMapName=kube-downscaler
```

or extracting and applying the template manually:

```bash
$ helm template kube-downscaler oci://ghcr.io/caas-team/charts/py-kube-downscaler --set nameOverride=kube-downscaler --set configMapName=kube-downscaler
```

### Migrate From Codeberg - Limited Access Installation

Read [Installation](#installation) section to understand what is meant for **Limited Access Installation**

```bash
$ helm install kube-downscaler oci://ghcr.io/caas-team/charts/py-kube-downscaler --set nameOverride=kube-downscaler --set configMapName=kube-downscaler --set constrainedDownscaler=true --set "constrainedNamespaces={namespace1,namespace2,namespace3}"
```

or extracting and applying the template manually:

```bash
$ helm template kube-downscaler oci://ghcr.io/caas-team/charts/py-kube-downscaler --set nameOverride=kube-downscaler --set configMapName=kube-downscaler --set constrainedDownscaler=true --set "constrainedNamespaces={namespace1,namespace2,namespace3}"
```

## Contributing

Easiest way to contribute is to provide feedback! We would love to hear what you like and what you think is missing.
Create an issue and we will take a look. PRs are welcome.

## License

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
Public License for more details.

You should have received a copy of the GNU General Public License along
with this program. If not, see <http://www.gnu.org/licenses/>.
