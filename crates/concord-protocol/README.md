# Concord Protocol

`concord-protocol` contains implementation-independent types and conformance rules for portable
Concord scientific records.

The crate follows three rules:

1. It remains useful without the Concord desktop application or production runtime.
2. It does not depend on product persistence, provider SDKs, or private services.
3. An implementation may enforce or extend a contract but may not silently redefine its serialized
   meaning.

The first implementation slice defines effect classes, approval cadence, reversibility semantics,
and portable capability permissions. Later slices will add canonical event, artifact, evidence,
execution, and replay contracts with cross-language fixtures.
