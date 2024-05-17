# Python Kubernetes Downscaler - Helm Chart

This repository offers a Helm chart for the `py-kube-downscaler`.

## Important values

| Key                | Type   | Example                                                                                               | Description                                     |
|--------------------|--------|-------------------------------------------------------------------------------------------------------|-------------------------------------------------|
| image.tag          | string | `"23.2.0@sha256:4129e7e7551eb451ee2b43680ef818f3057304ad50888f79ec9722afab6c29ff"`                    | Tag of the image to use                         |
| arguments          | list   | `[--interval=60,--include-resources=deployments,statefulsets,horizontalpodautoscalers,scaledobjects]` | Arguments to pass to the kube-downscaler binary |
| excludedNamespaces | list   | `["namespace-a", "namespace-b"]`                                                                      | Namespaces to exclude from downscaling          |
| extraConfig        | string | `"DOWNSCALE_PERIOD: 'Mon-Sun 19:00-20:00 Europe/Berlin'"`                                              | Additional configuration in ConfigMap format    |

# Deploy py-kube-downscaler using Helm chart

This directory contains a tutorial to deploy py-kube-downscaler.

## Configuring your Deployment to downscale

Please add below annotations based on timezone your deployment should run:

```yaml
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

```bash
kubectl config current-context
```

2. Before deploying, make sure to update **values.yaml** in py-kube-downscaler chart depending on whether you want RBAC
   roles deployed or not:

```yaml
rbac:
  create: false
```

Note: In case RBAC is enabled, a new service account will be created for py-kube-downscaler with certain privileges,
otherwise the 'default' one will be used.

3. Deploy py-kube-downscaler:
You can add our chart repository and deploy it by running:
```bash
helm repo add caas-team https://caas-team.github.io/helm-charts/

helm install py-kube-downscaler caas-team/py-kube-downscaler -n py-kube-downscaler
```

**OR**

You can alternatively clone this repository, change the current directory to the py-kube-downscaler repository and run:
```bash
helm install py-kube-downscaler ./chart -n py-kube-downscaler
```

4. Check the deployed release status:

```bash
helm list -n py-kube-downscaler
```

```
NAME                REVISION  UPDATED                   STATUS    CHART                     APP VERSION  NAMESPACE
py-kube-downscaler  1         Tue Sep 25 02:07:58 2018  DEPLOYED  py-kube-downscaler-0.5.1      0.5.1    py-kube-downscaler

```

5. Check whether py-kube-downscaler pod is up and running:

```bash
kubectl get pods -n py-kube-downscaler
```

```
NAME                                                     READY     STATUS    RESTARTS   AGE
py-kube-downscaler-py-kube-downscaler-7f58c6b5b7-rnglz   1/1       Running   0          6m
```

6. Check the Kubernetes event logs, to make sure the deployment of the py-kube-downscaler was successful:

```bash
kubectl get events -w
```

## Acknowledgments

Thanks to [Kube-downscaler](https://github.com/hjacobs/kube-downscaler) project authored
by [Henning Jacobs](https://github.com/hjacobs).
