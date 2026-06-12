---
title: "Authenticated ECH Config Distribution and Rotation"
abbrev: "Authenticated ECH Update"
category: std
ipr: trust200902
docname: draft-sullivan-tls-signed-ech-updates-latest
area: Security
workgroup: TLS
keyword:
  - TLS 1.3
  - Encrypted ClientHello
  - ECH
  - Key Rotation
  - RPK

author:
  - fullname: Nick Sullivan
    organization: Cryptography Consulting LLC
    email: nicholas.sullivan+ietf@gmail.com
  - fullname: Dennis Jackson
    organization: Mozilla
    email: ietf@dennis-jackson.uk
  - fullname: Alessandro Ghedini
    organization: Cloudflare
    email: alessandro@cloudflare.com

normative:
  RFC2119:
  RFC8174:
  RFC8446:
  RFC9180:
  RFC9460:
  RFC9849:
  I-D.ietf-tls-svcb-ech:
  I-D.ietf-tls-wkech:

venue:
  group: TLS
  type: Working Group
  github: grittygrease/draft-sullivan-tls-signed-ech-updates
---

--- abstract

Encrypted ClientHello (ECH) requires clients to have the
server's ECH configuration before connecting.  Currently,
when ECH fails, servers can send updated configurations but
clients cannot authenticate them unless the server has a
valid certificate for the public name, limiting deployment
flexibility.

This document specifies a new mechanism for authenticating
ECH configurations.  Servers include additional information
in their initial ECH configurations, which enables clients
to authenticate updated configurations without relying on a
valid certificate for the public name.

--- middle

# Introduction

Deployment of TLS Encrypted ClientHello (ECH) requires that
clients obtain the server's current ECH configuration
(ECHConfig) before initiating a connection.  Current
mechanisms distribute ECHConfig data via DNS SVCB and HTTPS
resource records {{!RFC9460}}{{!I-D.ietf-tls-svcb-ech}} or
HTTPS well-known URIs {{!I-D.ietf-tls-wkech}}, allowing
servers to publish their ECHConfigList prior to connection
establishment.

ECH includes a retry mechanism where servers can send an
updated ECHConfigList during the handshake.  The base ECH
specification instructs clients to authenticate this
information using a certificate valid for the public name
{{!RFC9849}}.

This forces a tradeoff between security and privacy for
server operators.  Using the same public name for as many
websites as possible improves client privacy, but makes
obtaining or compromising a valid certificate for that
public name a high value target for attackers.  It also
restricts the usable public names in an ECH deployment to
those for which operators can obtain valid certificates.

This document introduces an alternative authentication
mechanism for ECHConfig data which does not require the
server to hold a valid TLS certificate for the public
name.  This allows server operators to partition the retry
configuration between different domains, as well as
enabling greater flexibility in the public name used.

The mechanism authenticates updates with bare signing
keys identified by the hash of their
SubjectPublicKeyInfo.  A server's
initial ECHConfig lists the SHA-256 hashes of the
SubjectPublicKeyInfos of one or more public keys
authorized to sign updates, and each ECH Retry
Configuration carries a signature from one of those keys.
This replaces the need to authenticate the ECH Retry
configuration through the TLS handshake and ECH Public
Name.

# Conventions and Definitions

{::boilerplate bcp14}

This document assumes familiarity with TLS 1.3
{{!RFC8446}} and the ECH specification
{{!RFC9849}}, referred to here as simply "ECH".

## Terminology

ECHConfig:
: An individual ECH configuration structure as defined in
  {{!RFC9849}}, which includes fields such as
  `public_name`, `public_key` (an HPKE {{!RFC9180}} key),
  and extensions.

ECHConfigList:
: A sequence of one or more ECHConfig structures as
  defined in ECH (a byte string that starts with a 16-bit
  length and may contain multiple concatenated ECHConfig
  values).

ECHConfigTBS (To-Be-Signed):
: The serialized ECHConfig structure including the
  `ech_auth` extension, but with the `signature` field
  within `ech_auth` set to zero-length.  This includes all
  ECHConfig fields and the `ech_auth` extension's
  `not_after`, `disable`, `spki`, and `algorithm` fields.

signed ECHConfig:
: An ECHConfig that contains an `ech_auth` extension with
  a valid signature in the `signature` field, allowing
  clients to verify its authenticity.

public name:
: The value of the `public_name` field in the ECHConfig,
  i.e., the authoritative DNS name for updates and
  validation associated with that configuration.  This
  name is not required to be the ClientHelloOuter SNI,
  though deployments sometimes choose to align them.

retry_configs:
: The ECHConfigList sent by a server in
  EncryptedExtensions when ECH is rejected, as defined in
  {{!RFC9849}}.

outer SNI:
: The Server Name Indication value sent in the outer
  (unencrypted) ClientHello when ECH is used.  This is
  typically the ECHConfig's `public_name` or another name
  that preserves client privacy.

# Mechanism Overview

The server operator adds an `ech_authinfo` extension to the
ECHConfigs it advertises via DNS or other means. Each `ech_authinfo` extension
carries a set of `trusted_keys`, each value being
`SHA-256(SPKI)` of a public key that is authorized to
sign an ECH retry configuration.

When providing a retry configuration, the server operator
adds an `ech_auth`
extension holding the signing key (`spki`) and a
`signature`; it does not carry `trusted_keys`.  The client
validates it against the `trusted_keys` it recorded from
the initial configuration's `ech_authinfo` extension.

A client receiving such a configuration (e.g., in
EncryptedExtensions) extracts the signing key's
SubjectPublicKeyInfo (SPKI) from the `ech_auth` extension,
checks that its hash is one of the recorded `trusted_keys`,
checks that the configuration has not expired, and verifies
the signature using the signing key.  The normative
requirements for this validation are specified in
{{client-behavior}}.

A client that successfully validates a signed retry
configuration uses it to make a new connection attempt, in
line with the existing rules for ECH retries laid out in
the ECH specification.  Alternatively, the server can
indicate that ECH should not be used by setting `disable`
to `1` in a signed `ech_auth` extension, in which case the
validating client retries without ECH.

# Benefits of Signed ECH Configurations

By treating ECH configurations as signed objects, this
mechanism decouples trust in ECH keys from the TLS
handshake's certificate validation of the origin.  This
enables several important capabilities:

## Distinct Public Names Without CA Certificates

A server can use many different public hostnames (even
per-client, per-connection unique ones) without having
to obtain certificates for each.  This was not possible
under the original ECH design, which required a valid
certificate for any public name used
{{!RFC9849}}.

## Isolating Privacy-Critical Key Material

In a large CDN deployment, the ECH specification requires
many endpoints to have access to key material which can
authenticate a TLS connection for the public name.
This raises privacy and security risks where compromise of
the private key material in turn compromises the privacy
of ECH users and the security of normal TLS connections to
the public name.  The mechanism introduced in this document
avoids this sharing of private key material,
reducing the risk for ECH operators.

# Protocol Elements {#wire-formats}

This section specifies the new extensions and data
structures in detail.  All multi-byte values are in network
byte order (big-endian).  The syntax uses the TLS
presentation language from {{!RFC8446}}.

## ECH Authentication Extensions {#extensions}

The information for authenticating retry configs is carried
as an ECHConfig extension (`ech_authinfo`) inside the
ECHConfig structure and conveys authentication policy.  ECH
Retry Configs include an `ech_auth` extension which
carries the signing key and a signature, allowing clients
to verify the provided config independently of the TLS
handshake.

A single ECHConfig MUST NOT carry both extensions.
Initial configurations (for example, those published via
DNS) carry `ech_authinfo`; signed retry configurations
delivered in EncryptedExtensions carry `ech_auth`.  A
client MUST reject any ECHConfig that contains both.
Because a client performs at most a single retry per
connection attempt (per {{!RFC9849}}), a signed retry
configuration does not itself need to carry `trusted_keys`
for authenticating a subsequent update; on later
connections the client re-fetches the initial configuration
and its `ech_authinfo`.

The `ech_auth` extension MUST be the last extension in the
ECHConfig's extension list.  This simplifies ECHConfigTBS
construction: the signature field is at a fixed position
relative to the end of the serialized ECHConfig, so
implementations can set it to zero-length without parsing
earlier extensions.  Implementations MUST place this
extension last when constructing an ECHConfig, and MUST
reject ECHConfigs where `ech_auth` is not the last
extension.

The `ech_auth` and `ech_authinfo` extensions have the
following structure:

~~~~
    opaque SPKIHash<32..32>;

    struct {
      SPKIHash trusted_keys<32..2^16-1>;
    } ECHAuthInfo;

    struct {
        uint64 not_after; /* seconds since the Unix epoch */
        uint8 disable;    /* boolean: 0 = false, 1 = true */
        opaque spki<1..2^16-1>;
        SignatureScheme algorithm;
        opaque signature<1..2^16-1>;
    } ECHAuth;
~~~~

The `disable` field is a boolean.
When set to `1`, the client MUST NOT attempt ECH on the
retry.  The ECHConfig to which this `ech_auth` extension is
attached is then used only to carry and authenticate this
signal; its other contents (for example, its HPKE
`public_key`) MUST be ignored.  On successful validation the
client SHOULD clear any cached ECHConfig for this public
name and retry without ECH.  Senders MUST encode `disable` as `0` or `1`; clients
MUST reject any other value.

### Signature Computation

The signature is computed over the concatenation:

~~~~
    context_label = "TLS-ECH-AUTH-v1"
    to_be_signed = context_label || ECHConfigTBS
~~~~

where:

- `ECHConfigTBS` (To-Be-Signed) is the serialized
  ECHConfig structure including the `ech_auth` extension,
  but with the `signature` field within `ech_auth` set to
  zero-length.  That is, the two-byte length prefix of the
  `signature` field is encoded as `0x0000` and no signature
  bytes follow; this zero-length encoding is used only when
  constructing `ECHConfigTBS` and does not appear on the
  wire, where `signature` carries the actual signature.
  `ECHConfigTBS` includes all ECHConfig fields and the
  `ech_auth` extension's `not_after`, `disable`, `spki`, and
  `algorithm` fields.
- All multi-byte values use network byte order
  (big-endian).
- The serialization follows TLS 1.3 presentation language
  rules from {{RFC8446}}.

The `not_after` field is the number of seconds since the
Unix epoch (1970-01-01T00:00:00Z UTC, excluding leap
seconds), and bounds the replay window for a signed
configuration.  Shorter windows reduce the replay
window but require more frequent signature generation.
Longer windows allow pre-signing but increase exposure to
replayed configurations.  A window of 24 hours is
RECOMMENDED as a balance between operational simplicity
and replay resistance.

The `spki` field contains the DER-encoded
SubjectPublicKeyInfo of the signing key.  The client MUST
compute the SHA-256 hash of `spki`, verify that it matches
one of the hashes in `trusted_keys`, check that the
current time is before the `not_after` timestamp, and then
verify the signature with the public key in `spki`.  The
`not_after` field is REQUIRED and MUST be a timestamp
strictly greater than the client's current time at
verification.

The `algorithm` field is a `SignatureScheme` value from
{{!RFC8446}}.  The client MUST verify that `algorithm` is
consistent with the key type and parameters of the public
key carried in `spki` (for example, the curve of an ECDSA
key), and MUST reject the signed ECHConfig if it is not.
The signature is computed and verified according to the
rules for that `SignatureScheme` in {{!RFC8446}}.

Implementations MUST support `ecdsa_secp256r1_sha256`.
Implementations MAY support additional `SignatureScheme`
values and MUST be able to handle algorithm transitions.

The SPKI hash uses SHA-256 (value 4 in the IANA TLS
HashAlgorithm registry).  Allowing multiple hashes enables
seamless key rollovers.

Note: While TLS 1.3 moved to SignatureScheme and does not
directly use the HashAlgorithm enum, we reference the IANA
registry value for clarity.  Future versions of this
specification could add a hash algorithm field using the
TLS HashAlgorithm registry if algorithm agility becomes
necessary.

## TLS Behavior

### Server Behavior

When a server receives a ClientHello with the
`encrypted_client_hello` extension, it processes it per
{{!RFC9849}}. Depending on the outcome:

1. ECH Accepted: If the server successfully decrypts the
   ClientHelloInner, it completes the handshake using the
   inner ClientHello.

2. ECH Rejected: If the server cannot decrypt the
   ClientHelloInner, it SHOULD proceed with the outer
   handshake and include a signed retry ECHConfig in
   EncryptedExtensions.  This allows the client to
   immediately retry with the correct configuration.

The server may indicate that the client should attempt to
retry without ECH by setting `disable` to `1` in a
signed `ech_auth` extension.

A server that wishes to allow
authenticated updates MUST include `ech_authinfo` in the
ECHConfig it publishes via DNS or other means.  The server
MUST list, in `trusted_keys`, the SHA-256 hash of the SPKI
of every signing key that might sign an update before the
next ECHConfig change.  Multiple keys MAY be listed to
support key rotation.

### Client Behavior {#client-behavior}

When a client retrieves an ECHConfig (e.g., from DNS), it
examines the `ech_authinfo` extension and records the set
of `trusted_keys` for the duration of that connection
attempt only; these are not cached across connections.

During the TLS handshake, if ECH was not accepted by the server as defined in 6.1.4 of {{!RFC9849}}, the client follows the steps described in 6.1.6 of {{!RFC9849}}. However, rather than follow 6.1.7 of {{!RFC9849}}, it follows the steps below to determine if each provided ECH retry_config is authentic.

1. Validation: The retry_config MUST contain an `ech_auth`
   extension; a retry_config that does not is treated as
   failing validation.  The client computes the SHA-256 hash
   of the provided `spki`, verifies it matches one of the
   entries in `trusted_keys`, and verifies the signature
   using the public key contained in `spki`.

2. Validity Checking: The client verifies that
   `not_after` is strictly greater than the current time.

3. If steps 1 and 2 complete successfully:
     * The client treats the retry_config as authentic
       per {{RFC9849}}.
     * The client MUST terminate the connection and retry
       with the new ECHConfig or without ECH if indicated
       by the server.
     * The retry does not consider the server's TLS
       certificate for the public name.
     * The client need not validate any other provided retry_config.

4. If steps 1 or 2 do not complete successfully the client should process the remaining retry_configs (if any).

5. If no retry_config can be successfully authenticated, the client behaves as though the validation process described in 6.1.7 of {{!RFC9849}} has failed. The client MUST abort the connection with the appropriate alert and report the error to the calling application.

Note: Regardless of validation outcome in an ECH
rejection, the client will terminate the current
connection.  The difference is whether it retries with the
new config or ECH disabled (validation success) or treats it as a
certificate validation failure (validation failure).

### Backward Compatibility {#mandatory}

ECHConfig extensions, unlike TLS extensions, can be tagged
as mandatory by using an extension type codepoint with the
high order bit set to 1 {{!RFC9849}}.  A client
that does not understand a mandatory ECHConfig extension
MUST ignore the entire ECHConfig.

The `ech_authinfo` extension is always mandatory: the
codepoint assigned to it ({{iana}}) has the high-order bit
set.  As a consequence, a client that does not implement this
specification (a "legacy client") ignores the entire
ECHConfig and does not attempt ECH with it, connecting
directly or using another compatible configuration.  This
is the intended behavior: a legacy client would otherwise
attempt ECH and then be unable to authenticate any
`retry_configs` delivered on an ECH rejection (because, in
the deployments this document targets, the server may hold no
certificate valid for the public name), causing the
connection to fail.  Marking the extension mandatory ensures
such clients degrade gracefully rather than using a
configuration whose retry path they cannot complete.

Servers wanting to support both legacy clients and clients that understand this specification should offer multiple ECHConfigs, one with this extension, one without.

# Example Exchange

## Initial Setup

Consider `api.example.com` as a service protected by ECH
with public name `ech.example.net`.  The operator publishes
an ECHConfig via DNS HTTPS RR with the `ech_authinfo`
extension containing, in `trusted_keys`, the SHA-256 hash
of the SPKI of an ECDSA P-256 signing key (using the
mandatory-to-implement `ecdsa_secp256r1_sha256` scheme).

## Successful ECH

This flow works identically to existing ECH.

## ECH Rejection with Recovery

1. Client connects: Uses outdated ECHConfig
2. Server rejects ECH: Cannot decrypt inner ClientHello
3. Server continues outer handshake:
   - Sends signed ECHConfig in EncryptedExtensions
   - Uses TLS certificate for `foo.example.net` (the client
     does not validate this certificate; retry
     authentication uses the signed ECHConfig)
4. Client recovery:
   - Validates new ECHConfig via the signature it carries.
   - Closes connection
   - Immediately retries with new ECHConfig

# Security Considerations {#security}

## Passive Attackers

This mechanism preserves ECH's protection against passive
observation.  ECHConfig updates are delivered within the
EncryptedExtensions TLS message, preventing passive
observers from learning about configuration changes.  The
mechanism ensures that even during retry scenarios, the
client's intended server name is never exposed in
cleartext.

## Active Network Attackers

The security of this mechanism fundamentally depends on the
authenticity of the initial ECHConfig.  If an attacker can
inject a malicious initial configuration, the client's
privacy is compromised, but their connections remain
properly authenticated.

Initial retrieval of ECHConfigList via DNS is unchanged by
this mechanism.  This specification does not attempt to
authenticate the initial DNS fetch.  ECHConfigs obtained
via HTTPS from a well-known URI benefit from Web PKI
authentication.  Pre-configured ECHConfigs in applications
derive their trust from the application's distribution
channel.

### Retry Configuration Integrity

ECHConfigs delivered in EncryptedExtensions are usually
protected by TLS 1.3's handshake encryption and integrity
mechanisms.  The Finished message ensures that any
modification by an attacker would be detected.  The
authenticity of the Finished message is assured by
validating the server's certificate chain, which the client
checks is valid for the ECH Public Name.

However, signed ECHConfigs do not benefit from this handshake
authentication, because the client does not validate the server's
certificate chain.  Instead, the client verifies each ECHConfig against
the trusted keys recorded from the initial ECHConfig.  This
authenticates the configuration to the same trust anchor that a
certificate for the public name would, but, unlike a CertificateVerify
computed over the handshake transcript, the signature carries no
connection-specific input.

The `not_after` timestamp ensures configuration freshness.
This temporal bound prevents clients from accepting stale
configurations that might use compromised keys or outdated
parameters.

The requirements in 6.1.7 of {{!RFC9849}} already require clients to ignore
any session tickets or session ids presented by the server.

### Replay and Freshness of Signed Configurations

A signed ECHConfig is authenticated as a detached object rather than
through the connection that delivers it.  It is therefore valid in any
connection until its `not_after` time, and a party that obtains one (for
example, by requesting a retry configuration as an ordinary client) can
present it in other connections within that window.  This is an intended
consequence of the design: detaching the configuration from the
connection is what allows operators to sign updates offline and without
a certificate for the public name.

Replay is bounded.  An attacker cannot forge a configuration that was
never signed; it can only re-present one the operator actually issued,
and only until that configuration's `not_after`.  The `not_after` window
is the freshness bound on a signed configuration, so operators SHOULD
keep it as short as their signing cadence allows.  Removing a key's hash
from `trusted_keys` prevents acceptance of configurations signed by that
key once clients refetch the initial ECHConfig.

When rotating away from a compromised HPKE key, operators should note
that retry configurations signed before the rotation remain valid until
their `not_after`; an on-path attacker can replay one to steer a client
back onto the old key during that window.  Rotation is therefore not
complete until the last signed configuration referencing the retired key
has expired, and operators SHOULD choose `not_after` with this in mind.

Validation checks only that the signing key's hash appears in
`trusted_keys`; it does not bind a retry configuration to the initial
configuration it updates.  An operator that signs configurations for
multiple independent domains with a single key therefore allows a
configuration signed for one domain to validate when presented during a
connection to another.  To preserve the isolation this mechanism
provides for privacy-critical key material, operators SHOULD use a
separate signing key per isolation domain.

### Key Management

Servers MUST protect their ECH update signing keys.  If a
signing key is compromised, the server SHOULD remove its
hash from `trusted_keys`. As clients do not cache `trusted_keys` beyond
the lifetime of their initial connection attempt, this removal takes effect
as soon as the client is aware of the new ECHConfiguration, e.g. via DNS.

Servers SHOULD include multiple
keys in `trusted_keys` to facilitate key rotation and
recovery from compromise.

## Implementation Vulnerabilities

### Failure Handling

ECH connection attempts with signed updates are handled
identically to existing ECH connection attempts.  The only
difference is in how the server authenticates retry
configurations, not how it responds to the success or
failure of that authentication.

Algorithm agility is provided through the TLS
SignatureScheme registry.  As specified in
{{extensions}}, implementations MUST support
`ecdsa_secp256r1_sha256`, MAY support additional commonly
deployed algorithms, and MUST be able to handle algorithm
transitions.

### Denial of Service Considerations

The ECH specification allows ECH operators to decide which
ECH extensions to attempt to decrypt based on the public
ECHConfig ID advertised in the ClientHello and the public
name.  This extension reduces the value of those signals,
depending on the ECH operator's chosen configurations,
meaning that ECH operators may need to trial decrypt
incoming ECH extensions.

Attackers cannot force servers to send signed ECHConfigs
without establishing TLS connections.  Standard TLS
denial-of-service mitigations (rate limiting, stateless
cookies) apply equally to this mechanism.

# Privacy Considerations

This specification introduces no new privacy risks beyond
those already present in TLS and DNS when used with ECH.
ECHConfig updates are delivered within encrypted TLS
messages, preventing passive observers from learning about
configuration changes.  Server-directed ECH disablement
(a signed `ech_auth` with `disable` set to `1`) could
degrade privacy if signing keys are compromised, similarly to how
a valid TLS certificate for the public name could be used to disable ECH.

# IANA Considerations {#iana}

## ECHConfig Extension

IANA is requested to add the following entries to the
"ECH Configuration Extension Registry"
{{!RFC9849}}.  The codepoints assigned to
these extensions MUST have the high-order bit set, marking them
as mandatory ECHConfig extensions as described in
{{RFC9849}}.

- Extension Name: `ech_authinfo`
- Value: TBD1 (high-order bit set)
- Purpose: Conveys the set of public key hashes
  authorized to sign ECH retry configurations
- Reference: This document

- Extension Name: `ech_auth`
- Value: TBD2 (high-order bit set)
- Purpose: Conveys the signing key and signature for an
  ECH retry configuration
- Reference: This document

# Deployment Considerations {#deployment-considerations}

## Size Considerations

When sending signed ECHConfigs in EncryptedExtensions,
servers SHOULD be mindful of message size to avoid
fragmentation or exceeding anti-amplification limits.

## Key Rotation

Operators SHOULD publish updates well in advance of key
retirement.  Include appropriate `not_after` values for
each signed configuration.  Consider overlapping validity
windows to allow graceful client migration.

--- back

# Client Retry State Diagram {#appendix-a}

The following diagram shows client behavior upon ECH
rejection, when the server delivers retry_configs in
EncryptedExtensions.  The client validates each delivered
ECHConfig against the `trusted_keys` recorded from the
initial configuration, using the first one that
authenticates.  "ech_auth" refers to the authentication
extension within a delivered ECHConfig.

~~~~
    Receive retry_configs in EE
        (ECH was rejected)
                |
                v
      +------------------------+
      | More retry_configs     |<-------------+
      | left to validate?      |              |
      +------------------------+              |
         |                  |                 |
        yes                 no                |
         |                  |                 |
         v                  v                 |
   +----------------+   Treat as certificate  |
   | Validate next  |   validation failure;   |
   | config:        |   terminate connection; |
   |  - ech_auth    |   abort with alert;     |
   |    present     |   report error;         |
   |  - SPKI hash   |   do not retry.         |
   |    in          |                         |
   |    trusted_keys|                         |
   |  - signature   |                         |
   |    valid       |                         |
   |  - not_after   |                         |
   |    > now       |                         |
   +----------------+                         |
      |        |                              |
     no        yes                            |
      |        |                              |
      +--------|--- (try next config) --------+
               |
               v
         +-----------+
         | disable   |
         |  set?     |
         +-----------+
          |        |
         no        yes
          |        |
          v        v
    Terminate     Terminate connection;
    connection;   MUST NOT attempt ECH
    retry with    on retry; SHOULD
    new config.   clear cached config.
~~~~
{: #fig-retry title="Client Retry State Diagram"}

# Acknowledgments

The authors thank Martin Thomson for earlier contributions
and discussions on the initial draft.
