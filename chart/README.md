# Kube Downscaler Helm Chart

This repository offers a Helm chart for the `kube-downscaler` [project](https://codeberg.org/hjacobs/kube-downscaler).

## Important values

| Key                | Type   | Example                                                                                               | Description                                     |
| ------------------ | ------ | ----------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| image.tag          | string | `"23.2.0@sha256:4129e7e7551eb451ee2b43680ef818f3057304ad50888f79ec9722afab6c29ff"`                    | Tag of the image to use                         |
| arguments          | list   | `[--interval=60,--include-resources=deployments,statefulsets,horizontalpodautoscalers,scaledobjects]` | Arguments to pass to the kube-downscaler binary |
| excludedNamespaces | list   | `["namespace-a", "namespace-b"]`                                                                      | Namespaces to exclude from downscaling          |



# Deploy Kube-downscaler using Helm chart

This directory contains tutorial to deploy Kube-downscaler.

## Configuring your Deployment to downscale

Please add below annotations based on timezone your deployment should run:
```
metadata:
  annotations:
    downscaler/uptime: "Mon-Fri 07:00-19:00 US/Eastern"
```
Note: For more configuration details please, refer [here](https://github.com/hjacobs/kube-downscaler#configuration).

## Architecture
The diagram below depicts how a Kube-downscaler agent control applications.
![Alt text](images/architecture.png?raw=true "Kube Kube-downscaler diagram")

## Quick Start
Below are instructions to quickly install and configure Kube-downscaler.

### Installing Kube-downscaler

1. Make sure connected to right cluster:
```
kubectl config current-context
```
2. Set right environment depending on cluster:
```
export KDS_ENV='[minikube | testing | staging | production]'
```
3. Before deploy make sure to update *values.yaml* in Kube-downscaler chart depending on your cluster support for RBAC:
```
rbac:
  create: false
```
Note: In case RBAC is active new service account will be created for Kube-downscaler with certain privileges, otherwise 'default' one will be used.

4. Deploy Kube-downscaler:
```
helm install . --values "config/${KDS_ENV}.yaml" --namespace default  --name kube-downscaler
```

5. Check the deployed release status:
```
helm list
```
```
NAME            	REVISION	UPDATED                 	STATUS  	CHART                	APP VERSION	NAMESPACE
kube-downscaler      	1       	Tue Sep 25 02:07:58 2018	DEPLOYED	kube-downscaler-0.5.1	0.5.1      	default
```

6. Check Kube-downscaler pod is up and running:
```
kubectl get pods
```
```
NAME                                               READY     STATUS    RESTARTS   AGE
kube-downscaler-kube-downscaler-7f58c6b5b7-rnglz   1/1       Running   0          6m
```

7. Check Kubernetes event logs, to make sure of successful deployment of Kube-downscaler:
```
kubectl get events -w
```


## Acknowledgments

Thanks to [Kube-downscaler](https://github.com/hjacobs/kube-downscaler) project authored by [Henning Jacobs](https://github.com/hjacobs).
