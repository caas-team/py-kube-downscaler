# Python Kubernetes Downscaler - Helm Chart

This repository offers a Helm chart for the `py-kube-downscaler`.

## Important values

| Key                | Type   | Example                                                                                               | Description                                     |
|--------------------|--------|-------------------------------------------------------------------------------------------------------|-------------------------------------------------|
| image.tag          | string | `"23.2.0@sha256:4129e7e7551eb451ee2b43680ef818f3057304ad50888f79ec9722afab6c29ff"`                    | Tag of the image to use                         |
| arguments          | list   | `[--interval=60,--include-resources=deployments,statefulsets,horizontalpodautoscalers,scaledobjects]` | Arguments to pass to the kube-downscaler binary |
| excludedNamespaces | list   | `["namespace-a", "namespace-b"]`                                                                      | Namespaces to exclude from downscaling          |

# Deploy py-kube-downscaler using Helm chart

This directory contains tutorial to deploy py-kube-downscaler.

## Configuring your Deployment to downscale

Please add below annotations based on timezone your deployment should run:

```
metadata:
  annotations:
    downscaler/uptime: "Mon-Fri 07:00-19:00 US/Eastern"
```

Note: For more configuration details please,
refer [here](https://github.com/caas-team/py-kube-downscaler?tab=readme-ov-file#configuration).

## Architecture

The diagram below depicts how a py-kube-downscaler agent controls applications.
![Alt text](images/architecture.png?raw=true "Kube py-kube-downscaler diagram")

## Quick Start

Below are instructions to quickly install and configure py-kube-downscaler.

### Installing py-kube-downscaler

1. Make sure you're connected to the right cluster:

```
kubectl config current-context
```

2. Before deploying, make sure to update *values.yaml* in py-kube-downscaler chart depending on whether you want RBAC
   roles deployed or not:

```yaml
rbac:
  create: false
```

Note: In case RBAC is enabled, a new service account will be created for py-kube-downscaler with certain privileges,
otherwise the 'default' one will be used.

3. Deploy py-kube-downscaler:

```
cd chart
helm install . --namespace py-kube-downscaler --name py-kube-downscaler
```

4. Check the deployed release status:

```
helm list -n py-kube-downscaler
```

```
NAME                REVISION  UPDATED                   STATUS    CHART                     APP VERSION  NAMESPACE
py-kube-downscaler  1         Tue Sep 25 02:07:58 2018  DEPLOYED  py-kube-downscaler-0.5.1      0.5.1    py-kube-downscaler

```

5. Check whether py-kube-downscaler pod is up and running:

```
kubectl get pods -n py-kube-downscaler
```

```
NAME                                                     READY     STATUS    RESTARTS   AGE
py-kube-downscaler-py-kube-downscaler-7f58c6b5b7-rnglz   1/1       Running   0          6m
```

6. Check the Kubernetes event logs, to make sure of successful deployment of py-kube-downscaler:

```
kubectl get events -w
```

## Acknowledgments

Thanks to [Kube-downscaler](https://github.com/hjacobs/kube-downscaler) project authored
by [Henning Jacobs](https://github.com/hjacobs).
