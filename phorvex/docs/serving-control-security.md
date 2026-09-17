# Serving control security

Phorvex serving actions use `secure-required` by default. In that mode every
request goes to the selected Pod IP and declared serving port over verified
TLS. The TLS server name, CA and bearer Secret are chosen by an operator-owned
binding; Pod annotations cannot choose them. Missing or stale authority refuses
the action before its first mutation.

The version 1 configuration document has this exact shape:

```json
{
  "version": 1,
  "bindings": [{
    "namespace": "tenant-a",
    "policyName": "models",
    "policyUID": "9e7354cc-5b97-42f4-982d-8c531f03cf15",
    "serviceAccount": "model-runtime",
    "profileID": "models-admin-v1",
    "secretName": "models-serving-admin",
    "bearerKey": "bearer",
    "caKey": "ca.crt",
    "serverName": "models-admin.tenant-a.svc"
  }]
}
```

Keys and their spelling are exact. Unknown, duplicate, case-variant or trailing
fields fail startup. Each binding is unique by namespace, policy name, policy
UID and ServiceAccount. The referenced Secret is always read from the operator
namespace and must contain the named bearer and CA keys. The chart grants the
manager `get` for each exact Secret `resourceName`; it does not grant Secret
list, watch, write or access in tenant namespaces.

The binding digest stored in protected operation receipts covers the profile,
policy/workload scope, Secret reference and TLS server name. It excludes Secret
contents and Secret UID/resource version, so rotating the same Secret preserves
operation identity. Each dispatch or recovery attempt reads a fresh policy,
Pod and Secret and builds a short-lived client snapshot. Changing the binding
or server identity leaves pending work unresolved. Historical receipts remain
readable, but secure mode will not send their unbound HTTP work; independently
authorized Kubernetes compensation can still proceed.

`legacy-plaintext` is an explicit migration mode. It uses the historical Pod
annotation bearer over HTTP, is reported as insecure in capability status, and
does not satisfy this security contract. The chart rejects credential bindings
in legacy mode.

## Deployment verification

Perform these steps in a staging namespace with change approval. Replace every
example identity with the exact deployed policy UID and certificate identity.

1. Issue a server certificate from the selected private CA with the configured
   `serverName`. Configure the serving backend to require the bearer on its
   administrative routes. Store the CA bundle and bearer in the operator
   namespace:

   ```sh
   umask 077
   kubectl -n phorvex-system create secret generic models-serving-admin \
     --from-file=ca.crt=./ca.crt --from-file=bearer=./bearer
   ```

2. Render the chart with `phorvex.actuator=native` or `hybrid`,
   `phorvex.servingSecurity.mode=secure-required`, and an exact binding. Review
   the generated configuration, Secret `resourceNames`, Deployment arguments
   and read-only mount before applying it.

3. Verify the deployed manager identity can read only the configured Secret:

   ```sh
   kubectl auth can-i get secret/models-serving-admin -n phorvex-system \
     --as=system:serviceaccount:phorvex-system:phorvex-phorvex-manager
   kubectl auth can-i get secret/unrelated -n phorvex-system \
     --as=system:serviceaccount:phorvex-system:phorvex-phorvex-manager
   kubectl auth can-i list secrets -n phorvex-system \
     --as=system:serviceaccount:phorvex-system:phorvex-phorvex-manager
   ```

   The first result must be `yes`; the other two must be `no`.

4. From an approved diagnostic context with the same network reachability,
   prove the backend rejects a missing or wrong bearer, accepts the configured
   bearer over the configured CA/server name, and rejects a wrong CA or server
   name. Confirm no plaintext listener accepts the administrative route and no
   redirect leaves the Pod endpoint.

5. Rotate the backend's server certificate/key and accepted bearer, then prove
   the old bearer is denied by that backend. Separately update the manager's
   `ca.crt` and `bearer` data under the same Secret name. Confirm the next
   Phorvex attempt succeeds without changing the policy, profile or receipt
   identity. Updating the manager Secret alone does not revoke an old credential
   at the backend. Delete and recreate the Secret once in staging and verify
   requests remain refused during the absence and use only the recreated
   contents afterward.

6. Apply and validate a reviewed network policy based on
   `config/samples/serving-control-networkpolicy.example.yaml`. Confirm the
   manager reaches the administrative port, an unrelated workload cannot, and
   ordinary data-plane and DNS traffic still work.

Source tests use an isolated Kubernetes API and loopback TLS backend. They do
not prove the deployed backend requires authentication, certificate delivery,
CNI enforcement, request serving, or product-version compatibility. Those are
live acceptance conditions.
