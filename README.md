# kube-google-iam

Provide Google Cloud service account credentials to containers running inside a kubernetes cluster based on annotations.

This is a port to Google Cloud of https://github.com/jtblin/kube2iam

## Context

Traditionally in GCP, service level isolation is done using service accounts. Service accounts are assigned to GCE VMs
and software running inside them can access GCP services using the service account credentials via a metadata service.

## Problem statement

The problem is that in a multi-tenanted containers based world, multiple containers will be sharing the underlying
nodes. Given containers will share the same underlying nodes, providing access to GCP
resources via service accounts would mean that one needs to create a service account which is a union of all
service accounts. This is not acceptable from a security perspective.

## Solution

The solution is to redirect the traffic that is going to the metadata service for docker containers to a container
running on each instance, make a call to the GCP Service Accounts API to retrieve temporary access tokens for the
desired service account, and return these to the caller.

Some non-sensitive calls to the metadata service will be simply proxied through. This container will need to run with host networking enabled
so that it can call the metadata service itself.

## Usage

### Setup service accounts

The service account of your Kubernetes node VMs must have the role `roles/iam.serviceAccountTokenCreator` on the service
accounts you wish to assign to pods.

For example, if you want to make the `backup-agent` service account usable
from kubernetes pods, and your kubernetes node VMs run as the `k8s-node` service account:

```
$ gcloud iam service-accounts add-iam-policy-binding \
    backup-agent@my-project.iam.gserviceaccount.com
    --member=serviceAccount:k8s-node@my-project.iam.gserviceaccount.com \
    --role=roles/iam.serviceAccountTokenCreator
```

If you don't want to manually do this for every service account, you can bind the role for the entire project, which will allow using any service account in the project. Be aware of the security implications.

Also, make sure the instances are created with the scopes necessary for IAM API calls.

### kube-google-iam daemonset

Run the kube-google-iam container as a daemonset (so that it runs on each worker) with `hostNetwork: true`.
The kube-google-iam daemon and iptables rule (see below) need to run before all other pods that would require
access to the service account credentials.

Check the `deployment.yaml` file for a pre-made manifest, complete with RBAC bindings.

### iptables

To prevent containers from directly accessing the metadata service and gaining unwanted access to Google Cloud resources,
the traffic to `169.254.169.254` must be proxied for docker containers.

```bash
iptables \
  --append PREROUTING \
  --protocol tcp \
  --destination 169.254.169.254 \
  --dport 80 \
  --in-interface docker0 \
  --jump DNAT \
  --table nat \
  --to-destination 127.0.0.1:8181
```

This rule can be added automatically by setting `--iptables=true`, setting the `HOST_IP` environment
variable, and running the container in a privileged security context.

Note that the interface `--in-interface` above or using the `--host-interface` cli flag may be
different than `docker0` depending on which virtual network you use e.g.

* for Calico, use `cali+` (the interface name is something like cali1234567890
* for kops (on kubenet), use `cbr0`
* for CNI, use `cni0`
* for weave use `weave`
* for flannel use `cni0`

### Kubernetes annotation

Add an `cloud.google.com/service-account` annotation to your pods with the service account that you want the pod to use.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: cloud-sdk
  labels:
    name: cloud-sdk
  annotations:
    cloud.google.com/service-account: my-service-account@my-project.iam.gserviceaccount.com
spec:
  containers:
  containers:
  - image: google/cloud-sdk:latest
    command:
        - gcloud
        - compute
        - instances
        - list
    name: cloud-sdk
```

Pods without such annotation will not get any service account credentials. You can use `--default-service-account` to set a fallback service account to use in this case.

#### ReplicaSet, CronJob, Deployment, etc.

When creating higher-level abstractions than pods, you need to pass the annotation in the pod template of the  
resource spec.

Example for a `Deployment`:

```yaml
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: nginx-deployment
spec:
  replicas: 3
  template:
    metadata:
      annotations:
        cloud.google.com/service-account: my-service-account@my-project.iam.gserviceaccount.com
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.9.1
        ports:
        - containerPort: 80
```

Example for a `CronJob`:

```yaml
apiVersion: batch/v2alpha1
kind: CronJob
metadata:
  name: my-cronjob
spec:
  schedule: "00 11 * * 2"
  concurrencyPolicy: Forbid
  startingDeadlineSeconds: 3600
  jobTemplate:
    spec:
      template:
        metadata:
          annotations:
            cloud.google.com/service-account: my-service-account@my-project.iam.gserviceaccount.com
        spec:
          restartPolicy: OnFailure
          containers:
          - name: job
            image: my-image
```

### Namespace Restrictions

By using the flag --namespace-restrictions you can enable a mode in which the service accounts that pods can assume is restricted
by an annotation on the pod's namespace. This annotation should be in the form of a json array.

To allow the cloud-sdk pod specified above to run in the default namespace your namespace would look like the following.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  annotations:
    cloud.google.com/allowed-service-accounts: |
      ["my-service-account@my-project.iam.gserviceaccount.com"]
  name: default
```

_Note:_ You can also use glob-based matching for namespace restrictions.

Example: to allow all service accounts prefixed with `backup-` to be used by pods in the backups namespace, add the following annotation.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  annotations:
    cloud.google.com/allowed-service-accounts: |
      ["backup-*@my-project.iam.gserviceaccount.com"]
  name: backups
```

If you set a default service account with `--default-service-account`, it will be used on all pods without the annotation, even if it wouldn't be allowed by the namespace restriction.

### Debug

By using the --debug flag you can enable some extra features making debugging easier:

- `/debug/store` endpoint enabled to dump knowledge of namespaces and service account association.

### Options

By default, `kube-google-iam` will use the in-cluster method to connect to the kubernetes master, and use the
`cloud.google.com/service-account` annotation to retrieve the service account for the container.    

```bash
$ kube-google-iam --help
Usage of kube-google-iam:
    --api-server string                   Endpoint for the api server
    --api-token string                    Token to authenticate with the api server
    --app-port string                     Http port (default "8181")
    --backoff-max-elapsed-time duration   Max elapsed time for backoff when querying for service account. (default 2s)
    --backoff-max-interval duration       Max interval for backoff when querying for service account. (default 1s)
    --debug                               Enable debug features
    --default-service-account string      Fallback service account to use when annotation is not set
    --host-interface string               Interface on which to enable the iptables rule (default "docker0")
    --host-ip string                      IP address of host (default "127.0.0.1")
    --insecure                            Kubernetes server should be accessed without verifying the TLS. Testing only
    --iptables                            Add iptables rule (also requires --host-ip)
    --log-level string                    Log level (default "info")
    --metadata-addr string                Address for the metadata service. (default "169.254.169.254")
    --namespace-key string                Namespace annotation key used to retrieve the allowed service accounts (value in annotation should be json array) (default "cloud.google.com/allowed-service-accounts")
    --namespace-restrictions              Enable namespace restrictions
    --service-account-key string          Pod annotation key used to retrieve the service account (default "cloud.google.com/service-account")
    --verbose                             Verbose
    --version                             Print the version and exits
```

# Author

Port to work with Google Cloud service accoutns: Dario Nieuwenhuis, [@dirbaio](https://github.com/Dirbaio)
Original kube2iam for AWS by Jerome Touffe-Blin, [@jtblin](https://twitter.com/jtblin), [About me](http://about.me/jtblin)

# License

kube-google-iam is copyright 2017 Dario Nieuwenhuis, Jerome Touffe-Blin and contributors.
It is licensed under the BSD license. See the included LICENSE file for details.
