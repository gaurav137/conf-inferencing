Instructions to generate deploy-cluster.sh

- Use az cli for any Azure interactions.
- Use default Azure location as central india unless overridden.
- Always ensure any help usage in the script is up to date with the changes made per these instructions.
- Have any generated/downloaded files be placed under a "generated" folder under the folder that has deploy-cluster.sh script.
- Create a resource group in azure .The resource group name should have the format (<currently logged in username>-flex-test-rg).
- Creates an AAD enabled AKS cluster (don't enable Azure RBAC) adding the currently logged in user (via az login) as admin on the cluster.
  - The AKS cluster should use the dev/test configuration and is not meant for production.
  - Default node VM image size should be Standard_D4ds_v5 unless overridden.
  - Don't set any default kubernetes version and pass in the CLI unless a value is provided.
  - Don't set any default node cound and aass in the CLI unless a value is provided.
  - Don't specify any `--generate-ssh-keys` and `--tier` options.

Instructions to generate deploy-flex-node-vm.sh
- Assume a setup was created previously using deploy-cluster.sh.
  - Create a user assigned managed identity:
    - Hence forth referred to as kubelet-identity, will be used later as the AKS flex node identity used by kubelet.
    - Give Owner role on the cluster to this identity.
  - Get the kubelet-identity's object ID ($SP_OBJECT_ID) and setup kubernetes RBAC roles for the above identity using the following template:
      ```yaml
    # Create node bootstrapper role binding
    kubectl apply -f - <<EOF
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRoleBinding
    metadata:
      name: aks-flex-node-bootstrapper
    roleRef:
      apiGroup: rbac.authorization.k8s.io
      kind: ClusterRole
      name: system:node-bootstrapper
    subjects:
    - apiGroup: rbac.authorization.k8s.io
      kind: User
      name: $SP_OBJECT_ID
    EOF

    # Create node role binding
    kubectl apply -f - <<EOF
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRoleBinding
    metadata:
      name: aks-flex-node-role
    roleRef:
      apiGroup: rbac.authorization.k8s.io
      kind: ClusterRole
      name: system:node
    subjects:
    - apiGroup: rbac.authorization.k8s.io
      kind: User
      name: $SP_OBJECT_ID
    EOF
    ```
- Create an Ubuntu 22.04 Confidential VM (Canonical:0001-com-ubuntu-confidential-vm-jammy:22_04-lts-cvm:latest) with vTPM enabled, secure boot enabled, security type ConfidentialVM and OS disk security encryption type VMGuestStateOnly. Default VM size should be Standard_DC2as_v5 unless overridden:
  - VM should have SSH enabled and download the SSH private key file that can be used later to SSH into the VM post creation.
  - Wait for the VM to get a public IP and display the SSH command line to use to connect to the Azure VM using the private key file.
  - Generate a config file named 'aks-flex-node-config.json' with the following schema and filling in appropriate values for the placeholder values specified within <>:
    ```json
    {
      "azure": {
        "subscriptionId": "<insert-value-here>",
        "tenantId": "<insert-value-here>",
        "cloud": "AzurePublicCloud",
        "managedIdentity": {
          "clientId": "<user mi assigned client id value for kubelet-identity MI that was created>"
        },
        "targetCluster": {
          "resourceId": "<ARM ID of the AKS cluster that was created. Ensure resourcegroups in the ID is spelled as resourceGroups as its case sensitive.>",
          "location": "<Azure location being used>"
        }
      },
      "kubernetes": {
        "version": "<current kubernetes version that was used>"
      },
      "agent": {
        "logLevel": "debug",
        "logDir": "/var/log/aks-flex-node"
      }
    }
    ```
- Run the following commands in the Azure VM via SSH. You can generate a temporary shell script to gather the below steps and run them togther.
  - Run scripts/uninstall.sh script to cleanup any previous kubelet-proxy install.
  - 'curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash' if az cli is not installed.
  - az cli installation may fail with below error and if so retry it.
    Reading package lists...
    E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 2301 (dpkg)
    E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), is another process using it?
  - Run "curl -fsSL https://raw.githubusercontent.com/Azure/AKSFlexNode/refs/tags/v0.0.10/scripts/uninstall.sh | sudo bash -s -- --force" to cleanup a previous setup.
  - Copy the aks-flex-node-config.json generated config into the Azure VM into a folder named /etc/aks-flex-node as config.json.
  - Run "curl -fsSL https://raw.githubusercontent.com/Azure/AKSFlexNode/refs/tags/v0.0.10/scripts/install.sh | sudo bash" command in the Azure VM via ssh.
  - Run "sudo systemctl enable --now aks-flex-node-agent" to enable aks-flex-node-agent service.
  - Then wait for '/run/aks-flex-node/status.json' to appear which contains JSON content in the following schema:
    ```json
    {
      "kubeletVersion": "<string>",
      "runcVersion": "<string>",
      "containerdVersion": "<string>",
      "kubeletRunning": true,
      "kubeletReady": "<string>",
      "containerdRunning": true,
      "arcStatus": {
        "registered": false,
        "connected": false,
        "machineName": "<string>",
        "lastHeartbeat": "0001-01-01T00:00:00Z"
      },
      "lastUpdated": "<string>",
      "agentVersion": "<string>"
    }
    ```
    While waiting for the file to appear, check whether aks-flex-node-agent service has not failed and exited. If so, error out. If not show last 3 lines of journalctl -u output for aks-flex-node-agent.
    Wait for a few minutes for kubeletRunning value to be true and kubeletReady value to be Ready. Error out if this does not happen and invoke "journalctl -u aks-flex-node-agent --since" to dump some logs to help indicate the issue.
- If any of the SSH commands/script that are executed in the Azure VM fails then don't proceed further.
- Run kubectl get nodes to confirm that the Azure VM is showing up as a node on the AKS cluster. A node with the same name as the Azure VM name should appear.
- Add a taint "pod-policy=required:NoSchedule" on the above node to indicate only pods with a pod policy can be scheduled on it.
- Add a node selector label on the above node to help pods pick nodes that require pod policy.

Instructions to generate deploy-kubelet-proxy.sh
  - Assume a setup was created previously using deploy-cluster.sh and deploy-flex-node-vm.sh.
  - Generate signing keys using scripts/signing-tool.sh.
  - Run scripts/uninstall.sh script to cleanup any previous install.
  - Run scripts/install.sh script in the Azure VM via ssh using the --signing-cert-file and --local-binary options.

Instructions to generate test-pod-policies.sh
- Assume a setup was created previously using deploy-cluster.sh and deploy-kubelet-proxy.sh.
- Generate a sample pod yaml that conforms to the nginx-pod-policy.json file present under pod-policies.
  - The sample pod should have the toleration and node selector that was set on the VM node.
- Using signing-tool.sh to sign the nginx-pod-policy.json and have the policy and signature applied as annotations on the pod.
- Apply the pod yaml on the cluster and test that the pod gets scheduled on the Azure VM node and runs successfully
- Don't cleanup the sample pod so that it can be inspected after the test finishes.