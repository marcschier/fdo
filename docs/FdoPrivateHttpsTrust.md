# Private CA trust for FDO HTTPS runners

The public `FdoHttp` runners use platform trust unless the caller supplies
`FdoHttpPrivateTrust` for an HTTPS run. The configuration snapshots one DER
CA certificate. Each run creates a new HTTP client, with that certificate as
its only custom trust anchor. The platform still checks the server name,
certificate time, chain, and server authentication usage. A rejected
private chain does not fall back to platform roots. This policy does not
download missing certificates or check revocation.

Choose the anchor from host policy, not from an unverified redirect or
from the peer. Supply it to the runner overload for the selected endpoint
or attempt. Do not configure private trust for an HTTP address. The
transport still disables automatic redirects, proxies, and cookies; the
host still admits the destination and controls any stricter DNS and SNI
requirements. The TLS policy does not replace voucher, Device attestation,
or Delegate trust checks and does not modify any system trust store.
