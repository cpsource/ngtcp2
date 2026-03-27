Do not try to make a certificate that “doesn’t really expire.” In X.509, the validity window is a core part of the certificate model: a cert has a `notBefore` and `notAfter`, and outside that window it is no longer valid. ([RFC Editor][1])

A better design is to keep expiration, but make renewal automatic and safe.

The cleanest pattern is this:

1. Give each node or service a **longer-lived enrollment identity** that is not used directly for normal connections.
2. Use that identity only to obtain a **short-lived operational certificate**.
3. Renew the short-lived cert automatically before it expires.
4. Make peers trust only the short-lived cert for actual network auth.

That gets you the benefit you want — uninterrupted operation — without weakening the trust model. Short cryptoperiods are a standard security win because they reduce the exposure window of compromised keys. ([NIST Computer Security Resource Center][2])

## What your “flexi-cert” should really be

Think of it as a **renewable session identity**, not a non-expiring cert.

A good design is:

* **Root CA / intermediate CA**
  Your normal PKI trust anchor.

* **Enrollment credential**
  A long-lived device cert, TPM-bound key, hardware key, or bootstrap secret.
  This is only for talking to your internal issuer.

* **Issuer / registration service**
  Authenticates the client using the enrollment credential and issues a new short-lived leaf cert.

* **Operational cert**
  Very short-lived leaf cert used for mTLS or network admission, maybe valid for hours or days.

This is basically the model used by systems like SPIFFE/SPIRE, which issue short-lived X.509 identities to workloads rather than relying on static long-lived certs. ([SPIFFE][3])

## Why this is better than bypassing expiry

If you let expired certs keep working, you create four problems:

* you lose a hard stop on stale credentials
* key compromise lasts longer
* decommissioned systems may keep authenticating
* incident response gets much harder

Modern practice is moving the other direction: shorter cert lifetimes with heavy automation. Let’s Encrypt now offers very short-lived certs and explicitly recommends automated renewal. ([Let's Encrypt][4])

## Practical patterns you can use

### Pattern A: Renewable leaf certificate

This is usually the best answer.

How it works:

* Client has enrollment credential `E`
* Client connects to internal issuer
* Issuer checks `E`, device posture, policy, maybe IP/location/attestation
* Issuer signs a fresh leaf cert `Cshort`
* Client uses `Cshort` for mTLS to other services
* Client renews at 50–80% of lifetime

Example lifetimes:

* Enrollment credential: 6–12 months
* Operational cert: 8 hours, 24 hours, or 7 days

This gives you continuity without weakening auth.

### Pattern B: Overlapping certificates

To avoid outages during rotation:

* issue new cert before old one expires
* keep both in memory briefly
* new connections use new cert
* existing sessions finish on old cert

This is simple and effective.

### Pattern C: Grace period with re-authentication

If a leaf cert expires, do **not** keep accepting it for normal access.
Instead allow only a narrow re-enrollment flow:

* expired leaf can contact only the issuer
* issuer demands stronger proof: enrollment cert, TPM attestation, hardware token, or admin-approved refresh
* issuer returns a fresh cert

That gives resilience without making expired certs broadly valid.

### Pattern D: Certificate + signed authorization token

Sometimes the cert should identify the machine, and a separate short-lived token should authorize the connection.
So:

* mTLS cert = identity
* signed token = permission to join network / access service

This is useful when authorization changes more often than identity.

## A concrete “flexi-cert” design

If you want to invent your own mechanism, make it this:

**Flexi-cert package**

* Device keypair `K_device` stored in TPM/HSM if possible
* Long-lived enrollment certificate `Cert_enroll`
* Short-lived connection certificate `Cert_conn`
* Renewal endpoint `/renew`
* Policy engine that can deny renewal if device is revoked, quarantined, or out of compliance

**Renewal flow**

1. Device notices `Cert_conn` expires soon.
2. Device opens mTLS to issuer using `Cert_enroll`.
3. Device signs a nonce with `K_device`.
4. Issuer checks:

   * `Cert_enroll` still valid
   * device not revoked
   * device matches inventory
   * optional attestation / health checks
5. Issuer returns new `Cert_conn`.
6. Device hot-reloads the cert without restarting.

**Important rule:**
`Cert_enroll` should not be accepted by your production services. Only the issuer should accept it.

That separation is what keeps the design safe.

## Extra hardening

For a serious system, add these:

* bind private keys to **TPM**, HSM, smartcard, or secure enclave
* use a **renewal window** so clients renew well before expiry
* include **device ID / workload ID** in SAN or URI SAN
* maintain a **revocation list / denylist** for enrollment identities
* require **attestation** for high-trust devices
* log every issuance and renewal
* use short-lived leaf certs so revocation matters less

## What not to do

Avoid these designs:

* “accept expired certs for 30 days”
* “ignore notAfter if the CN is known”
* “special extension that says this cert can outlive expiry”
* “let peers locally decide to keep trusting stale certs”

Those all undermine PKI semantics and create silent security debt.

## Best recommendation

If this is for machines/services inside your own environment, I would build it like this:

* private CA
* long-lived enrollment identity per node/device
* automatic issuer service
* short-lived connection certs
* hot reload before expiry
* immediate renewal denial for revoked or unhealthy nodes

In other words, solve expiry operationally, not by trying to defeat it.

If you want, I can sketch a concrete protocol for this in Python terms, or map it onto Ubuntu services with OpenSSL, step-ca, or SPIRE.

[1]: https://www.rfc-editor.org/rfc/rfc5280.html?utm_source=chatgpt.com "RFC 5280: Internet X.509 Public Key Infrastructure ..."
[2]: https://csrc.nist.gov/glossary/term/cryptoperiod?utm_source=chatgpt.com "Cryptoperiod - Glossary | CSRC"
[3]: https://spiffe.io/docs/latest/spiffe-about/overview/?utm_source=chatgpt.com "SPIFFE Overview"
[4]: https://letsencrypt.org/docs/faq/?utm_source=chatgpt.com "FAQ"

