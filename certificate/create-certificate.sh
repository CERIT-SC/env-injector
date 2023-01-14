base="env-injector-mw"
service="${base}-svc"
secret="${base}-cert-secret"
namespace="env-injector"
context="kubt-cluster"
csrName=${service}.${namespace}

#openssl genrsa -out client.key 2048
# https://github.com/kubernetes/kubernetes/issues/99504
#openssl req -new -key client.key -subj "/CN=system:node:env-injector-mw-svc.env-injector^Cvc;/O=system:nodes" -out client.csr -config csr.conf

# clean-up any previously created CSR for our service. Ignore errors if not present.
kubectl config use-context ${context}
kubectl delete csr ${csrName} 2>/dev/null || true

# Use K8s built-in signer kubelet-serving
# https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#kubernetes-signers
cat <<EOF | kubectl create -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: ${csrName}
spec:
  groups:
  - system:authenticated
  request: $(cat client.csr | base64 | tr -d '\n')
  signerName: kubernetes.io/kubelet-serving
  usages:
  - digital signature
  - key encipherment
  - server auth
EOF

# verify CSR has been created
while true; do
    kubectl get csr ${csrName}
    if [ "$?" -eq 0 ]; then
        break
    fi
done
kubectl certificate approve ${csrName}
for x in $(seq 10); do
    serverCert=$(kubectl get csr ${csrName} -o jsonpath='{.status.certificate}')
    if [[ ${serverCert} != '' ]]; then
      break
    fi
    sleep 1
done
sleep 10
serverCert=$(kubectl get csr ${csrName} -o jsonpath='{.status.certificate}')
if [[ ${serverCert} == '' ]]; then
    echo "ERROR: After approving csr ${csrName}, the signed certificate did not appear on the resource. Giving up after 10 attempts." >&2
    exit 1
fi

echo -n ${serverCert} | base64 -d > server.crt
# for some unknown reason, server cert is not saved properly but as binary file
# must check if it is BEGIN CERTIFICATE !!

# create the secret with CA cert and server cert/key
kubectl create secret generic ${secret} \
        --from-file=tls.key=client.key \
        --from-file=tls.crt=client.csr \
        --from-file=ca.crt=server.crt \
        --dry-run -o yaml |
    kubectl -n ${namespace} apply -f -

# If cert-manager is installed
# https://cert-manager.io/docs/concepts/ca-injector/#injecting-ca-data-from-a-secret-resource
kubectl annotate secret ${secret} cert-manager.io/allow-direct-injection="true" -n ${namespace}