# ACM Cert Manager Addon

This is a proof of concept. Do not use.

## Prereqs

- RHACM Hub Cluster
- At least 1 managed cluster imported/deployed with the RHACM Cluster

## Deploying the addon

1. Deploy cert-manager operator in the Hub cluster.

2. Configure ACM ClusterIssuer in the hub cluster.

3. Run the addon in the hub cluster (At this point, I'm running the addon in my laptop using the Hub's kubeconfig):

    ~~~sh
    export KUBECONFIG=/path/to/hub/kubeconfig
    go run main.go
    ~~~

4. The addon will create policies for secrets generated by CertManager inside a ManagedCluster namespace