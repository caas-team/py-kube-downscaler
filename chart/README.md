# Kube Downscaler Helm Chart

This repository offers a convenience chart for the `kube-downscaler` [project](https://codeberg.org/hjacobs/kube-downscaler).

## Important values

| Key                | Type   | Example                                                                                               | Description                                     |
| ------------------ | ------ | ----------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| image.tag          | string | `"23.2.0@sha256:4129e7e7551eb451ee2b43680ef818f3057304ad50888f79ec9722afab6c29ff"`                    | Tag of the image to use                         |
| arguments          | list   | `[--interval=60,--include-resources=deployments,statefulsets,horizontalpodautoscalers,scaledobjects]` | Arguments to pass to the kube-downscaler binary |
| excludedNamespaces | list   | `["namespace-a", "namespace-b"]`                                                                      | Namespaces to exclude from downscaling          |

How the downscaler can be configured is described in the [kube-downscaler documentation](https://codeberg.org/hjacobs/kube-downscaler).
