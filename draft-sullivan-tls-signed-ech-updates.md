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
  - PKIX
  - RPK

author:
  - fullname: Nick Sullivan
    organization: Cryptography Consulting LLC
    email: nicholas.sullivan+ietf@gmail.com
  - fullname: Dennis Jackson
    organization: Mozilla
    email: ietf@dennis-jackson.uk

normative:
  RFC2119:
  RFC8174:
  RFC8446:
  RFC9180:
  RFC9460:
  I-D.ietf-tls-esni:
  I-D.ietf-tls-svcb-ech:
  I-D.ietf-tls-wkech:

informative:

venue:
  group: TLS
  type: Working Group
  github: grittygrease/draft-sullivan-tls-signed-ech-updates
---

--- abstract

Encrypted ClientHello (ECH) requires clients to have the server's ECH configuration before connecting. Currently, when ECH fails, servers can send updated configurations but clients cannot authenticate them unless the server has a valid certificate for the public name, limiting deployment flexibility.

This document specifies a new mechanism for authenticating ECH configurations. Servers include additional information in their initial ECH configurations, which enables clients to authenticate any updated configurations without relying on a valid certificate for the public name.

--- middle

# Introduction

Deployment of TLS Encrypted ClientHello (ECH) requires that clients obtain the server's current ECH configuration (ECHConfig) before initiating a connection. Current mechanisms distribute ECHConfig data via DNS HTTPS resource records {{!RFC9460}} or HTTPS well-known URIs {{!I-D.ietf-tls-wkech}}, allowing servers to publish their ECHConfigList prior to connection establishment.

ECH includes a retry mechanism where servers can send an updated ECHConfigList during the handshake, the base ECH specification instructs clients to authenticate this information using a certificate valid for the public name {{!I-D.ietf-tls-esni}}.

This forces a tradeoff between security and privacy for server operators. Using the same public name for as many websites as possible improves client privacy, but makes obtaining or compromising a valid certificate for that cover name a high value target for attackers. It also restricts the usable public names in an ECH deployment to those for which operators can obtain valid certificates.

This document introduces an alternative authentication mechanism for ECHConfig data which doesn't rely on the public name used in the initial ECHConfig. This allows server operators to partition the retry configuration between different domains, as well as enabling a greater flexibility in the public name used.

The mechanism supports two authentication methods:

1. Raw Public Key (RPK) - Uses SPKI hashes to identify public keys for retry authentication.
2. PKIX - Uses certificate-based signing with a critical X.509 extension.

Each ECH Retry Configuration carries at most one signature using the specified method, replacing the need to authenticate the ECH Retry configuration through the TLS handshake and ECH Public Name.

# Conventions and Definitions

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" in this document are to be interpreted as described in BCP 14 {{!RFC2119}} {{!RFC8174}} when, and only when, they appear in all capitals.

This document assumes familiarity with TLS 1.3 {{!RFC8446}} and the ECH specification {{!I-D.ietf-tls-esni}}, referred to here as simply "ECH".

The following acronyms are used throughout this document:

- RPK: Raw Public Key - A public key used directly without a certificate wrapper
- PKIX: Public Key Infrastructure using X.509 - The standard certificate-based PKI used on the web
- SPKI: SubjectPublicKeyInfo - The ASN.1 structure containing a public key and its algorithm identifier
- HPKE: Hybrid Public Key Encryption - The encryption scheme used by ECH as defined in {{!RFC9180}}
- DER: Distinguished Encoding Rules - A binary encoding format for ASN.1 structures
- CA: Certificate Authority - An entity that issues digital certificates

## Terminology

ECHConfig:
: An individual ECH configuration structure as defined in {{!I-D.ietf-tls-esni}}, which includes fields such as `public_name`, `public_key` (HPKE key), and extensions.

ECHConfigList:
: A sequence of one or more ECHConfig structures as defined in ECH (a byte string that starts with a 16-bit length and may contain multiple concatenated ECHConfig values).

ECHConfigTBS (To-Be-Signed):
: The serialized ECHConfig structure with the `ech_auth` extension, but with the `signature` field within `ech_auth` set to zero-length. This includes all ECHConfig fields and the `ech_auth` extension's `method` and `trusted_keys` fields.

signed ECHConfig:
: An ECHConfig that contains an `ech_auth` extension with a valid signature in the `signature` field, allowing clients to verify its authenticity.

public name:
: The value of the `public_name` field in the ECHConfig, i.e., the authoritative DNS name for updates and validation associated with that configuration. This name is not required to be the ClientHelloOuter SNI, though deployments sometimes choose to align them.

retry_configs:
: The ECHConfigList sent by a server in EncryptedExtensions when ECH is rejected, as defined in {{!I-D.ietf-tls-esni}}.

outer SNI:
: The Server Name Indication value sent in the outer (unencrypted) ClientHello when ECH is used. This is typically the ECHConfig's `public_name` or another name that preserves client privacy.

The reader should recall that in TLS 1.3, the server's EncryptedExtensions message is encrypted and integrity-protected with handshake keys {{!I-D.ietf-tls-esni}}. New extensions defined as part of EncryptedExtensions are not visible to network attackers and cannot be modified by an attacker without detection. Additionally, "certificate verification" refers to the standard X.509 validation process (chain building, signature and expiration checking, name matching, etc.) unless otherwise specified.

# Mechanism Overview

This specification defines two methods for authenticating ECH configuration updates:

Raw Public Keys (RPK) has little wire overhead and no external dependencies. The site offering ECH places one or more public key hashes in their ECH Configs, then can use those keys to sign ECH Retry Configs. However, key rotation must be managed by the site operator, through updates to the list of trusted public key hashes.

PKIX has a larger wire overhead and requires coordination with an issuing CA - who must provide certificates with an appropriate extension. However, it doesn't require any manual key rotation. The public name used to authenticate the certificate is a fixed string, which is never visible on the wire, and the operator can rotate certificate chains without any needing to change their advertised ECHConfigs.

## Raw Public Key (RPK)

The ECHConfigList update is authenticated by a Raw Public Key (RPK). The ECHConfig's `ech_authinfo` extension carries a set of `trusted_keys`, each value being `SHA-256(SPKI)` of an RPK that is authorized to sign an update.

A client receiving a signed ECH retry configuration (e.g., in Encrypted Extensions) MUST:

1. Extract the authenticator key's SubjectPublicKeyInfo (SPKI) and compute `sha256(spki)`. Verify membership in `trusted_keys`.
2. Verify that `not_after` is strictly greater than the client's current time.
3. Verify the signature over the ECH Configuration and the `not_after` using the authenticator's public key.

The client may then use the signed ECH retry configuration to make a new connection attempt, in line with the existing rules for ECH retrys laid out in the ECH specification. Alternatively, if the server wants the client to disable ECH then it can produce a signature over an empty ECHConfig to indicate that.

## PKIX (Certificate-Based)

The update is signed with the private key corresponding to an X.509 certificate that chains to a client trusted root and is valid for the ECHConfig `public_name` (i.e., appears in the certificate's SAN).

The leaf certificate MUST include a new, critical X.509 v3 extension `id-pe-echConfigSigning` (OID: TBD) whose presence indicates authorization to sign ECH configuration updates for the DNS names in the certificate's SAN. Clients:

- MUST validate the certificate chain according to local policy;
- MUST confirm the SAN covers the ECHConfig `public_name`;
- MUST confirm the critical `id-pe-echConfigSigning` extension is present in the leaf; and
- MUST verify the ECH signature with the leaf key.
- MUST verify that the `not_after` field in `ech_auth.signature` is strictly greater than the client's current time.

When this critical extension is present, clients MUST NOT accept the certificate for TLS server authentication. The use of a the critical bit ensures that even clients who are unaware of the extension, will not accept it for TLS server authentication.

# Benefits of Signed ECH Configurations

By treating ECH configurations as signed objects, this mechanism decouples trust in ECH keys from the TLS handshake's certificate validation of the origin. This enables several important capabilities:

## Distinct Public Names Without CA Certificates

A server can use many different public hostnames (even per-client, per-connection unique ones) for other operational reasons {{!I-D.ietf-tls-esni}}, without having to obtain certificates for each. This was not possible under the original ECH design, which required a valid certificate for any public name used {{!I-D.ietf-tls-esni}}.

## Isolating privacy-critical key material

In a large CDN deployment, the ECH specification requires many endpoints to have access to key material which can authenticate a TLS connection for the ECH Cover Name. This raises privacy and security risks - where compromise of the private key material in turn compromises the privacy of ECH users and the security of normal TLS connections to the cover name. Both the mechanisms introduced in this document avoid this problematic sharing of private key material, reducing the risk for ECH operators.

# Protocol Elements {#wire-formats}

This section specifies the new extensions and data structures in detail. All multi-byte values are in network byte order (big-endian). The syntax uses the TLS presentation language from {{!RFC8446}}.

## ECH authentication extensions (`ech_auth`)

The information for authenticating retry configs is carried as an ECHConfig extension (`ech_authinfo`) inside the ECHConfig structure and conveys authentication policy. ECH Retry Configs include an `ech_auth` extension which includes signed authenticator that allows clients to verify the provided config independently of the TLS handshake.

The `ech_auth` extension MUST be the last extension in the ECHConfig's extension list. This ensures that the signature in the extension covers all other extensions in the ECHConfigTBS. Implementations MUST place this extension last when constructing an ECHConfig, and MUST reject ECHConfigs where `ech_auth` is not the last extension.

The `ech_auth` and`ech_authinfo` extensions have the following structure:

    enum {
        rpk(0),
        pkix(1),
        (255)
    } ECHAuthMethod;

    // We reuse the TLS HashAlgorithm registry values (though TLS 1.3 itself
    // doesn't use this enum directly, the registry still exists)
    // For now, implementations MUST use sha256(4). Future specs may allow others.
    opaque SPKIHash<32..32>;  // SHA-256 hash of DER-encoded SPKI

struct {
      ECHAuthMethod method;              // Single authentication method
      SPKIHash trusted_keys<0..2^16-1>;  // RPK-only; SHA-256 hashes per IANA TLS
    } ECHAuthInfo;

  struct {
    ECHAuth method
    uint64 not_after;
    opaque authenticator<1..2^16-1>; //Holds either RPK DER or PKIX certificate
    SignatureScheme algorithm;
        opaque signature<1..2^16-1>;
      } signature;
  } ECHAuth

### Signature Computation

The signature is computed over the concatenation:

    context_label = "TLS-ECH-AUTH-v1"  // ASCII, no NUL
    to_be_signed = context_label || ECHConfigTBS

where:

- `ECHConfigTBS` (To-Be-Signed) is the serialized ECHConfig structure including
  the `ech_auth` extension, but with the `signature` field within `ech_auth`
  set to zero-length. This means it includes:
  - All ECHConfig base fields (version, length, contents, etc.)
  - All extensions including `ech_auth` (which MUST be last)
  - Within `ech_auth`: the `method`, and the authenticator/
    not_after/algorithm fields from `signature`, but NOT the actual signature
    bytes
- The signature is computed over this entire structure.
- All multi-byte values use network byte order (big-endian)
- The serialization follows TLS 1.3 presentation language rules from RFC 8446

Method-specific `authenticator`:

- RPK (method=0): the DER-encoded SubjectPublicKeyInfo (SPKI) of the signing key. The client MUST compute the SHA-256 hash of the SPKI, verify that it matches one of the hashes in `trusted_keys`, check that the current time is before the `not_after` timestamp, and then verify the signature with this key. The `not_after` field is REQUIRED and MUST be a timestamp strictly greater than the client's current time at verification.
- PKIX (method=1): a CertificateEntry vector (leaf + optional intermediates) as in TLS 1.3 Certificate; the leaf MUST include the critical `id-pe-echConfigSigning` extension and be valid for the ECHConfig `public_name`. The client validates the chain, confirms the SAN includes the ECH `public_name`, confirms the critical `id-pe-echConfigSigning` extension is present in the leaf, and verifies the signature with the leaf key. The `not_after` field MUST be a timestamp strictly greater than the client's current time at verification.

Notes:

- `trusted_keys` is only used by RPK; clients MUST ignore it for PKIX.
- If `method` is `rpk(0)`, `trusted_keys` MUST contain at least one SPKI hash; otherwise it MUST be zero-length.
- A server publishing multiple ECHConfigs MAY use different methods for each to maximize client compatibility.

Context-specific requirements:

- When carried in TLS (EncryptedExtensions), an `ech_auth` extension in each delivered ECHConfig MUST include a signed authenticator in `signature`, and the client MUST verify the authenticator before installing the ECHConfig.
- When carried in DNS, an `ech_authinfo` extension conveys only policy (`method`, `trusted_keys`).

The SPKI hash uses SHA-256 (value 4 in the IANA TLS HashAlgorithm registry). Allowing multiple hashes enables seamless key roll overs.

Note: While TLS 1.3 moved to SignatureScheme and doesn't directly use the HashAlgorithm enum, we reference the IANA registry value for clarity. Future versions of this specification could add a hash algorithm field using the TLS HashAlgorithm registry if algorithm agility becomes necessary.

Client behavior: When a client obtains an ECHConfig that contains an `ech_authinfo` extension, it SHOULD store this information along with the configuration.

Server behavior: A server that wishes to allow authenticated updates MUST include `ech_authinfo` in the ECHConfig it publishes via DNS or other means. The server MUST set the `method` field to the authentication method it will use for this configuration. The server MUST ensure that it actually has the capability to perform the indicated method:

- If `method` is `rpk(0)`, the server needs a signing key whose SPKI hash is in `trusted_keys`. (It may have multiple keys for rotation; all keys that might sign an update before the next ECHConfig change should be listed.
- If `method` is `pkix(1)`, the server must have a valid certificate (and chain) for the public name with the critical `id-pe-echConfigSigning` extension (Section [IANA Considerations](#iana) defines the extension) available at runtime to use for signing. The certificate's public key algorithm dictates what signature algorithms are possible.

## TLS Extensions for ECH Config Update

### EncryptedExtensions Delivery

This specification reuses the ECH retry_configs delivery mechanism: the server sends an ECHConfigList where each ECHConfig contains the `ech_auth` extension with a signed authenticator. The server MAY include multiple ECHConfigs with different authentication methods (e.g., one with PKIX and one with RPK).

### Server Behavior

When a server receives a ClientHello with the `encrypted_client_hello` extension, it processes ECH per {{!I-D.ietf-tls-esni}}. If the server has an updated ECHConfigList to distribute:

1. ECH Accepted: If the server successfully decrypts the ClientHelloInner, it completes the handshake using the inner ClientHello.

2. ECH Rejected: If the server cannot decrypt the ClientHelloInner, it SHOULD proceed with the outer handshake and include signed ECHConfigs in EncryptedExtensions. This allows the client to immediately retry with the correct configuration.

The server may indicate that the client should attempt to retry without ECH by including an ECHAuth extension over an empty config.

### Client Behavior

When a client retrieves an ECHConfig (e.g., from DNS), it examines the `ech_authinfo` extension and records:

- The authentication `method` (RPK or PKIX)
- Any `trusted_keys` for RPK validation

During the TLS handshake, upon receiving an ECHConfigList in EE:

1. Validation: The client validates the authenticator according to its method:
   - RPK: Computes the SHA-256 hash of the provided SPKI, verifies it matches one in `trusted_keys`, then verifies the signature
   - PKIX: Validates the certificate chain, verifies the leaf certificate covers the ECHConfig's `public_name`, checks for the critical `id-pe-echConfigSigning` extension, then verifies the signature

2. Validity Checking: The client checks temporal validity:
   - For RPK: Verifies current time is before `not_after`
   - For PKIX: Verifies certificate validity period (the `not_after` field MUST be 0)

3. Installation and Retry (see Appendix A for state diagram):
   - If validation succeeds and this was an ECH rejection (outer handshake):
     * The client treats the retry_configs as authentic per {{I-D.ietf-tls-esni, Section 6.1.6}}
     * The client MUST terminate the connection and retry with the new ECHConfig or without ECH if indicated by the server.
     * The retry does not consider the server's TLS certificate for the public name
   - If validation succeeds and this was an ECH acceptance:
     * No changes to the ECH specification
   - If validation fails:
     * The client MUST treat this as if the server's TLS certificate could not be validated
     * The client MUST NOT use the retry_configs
     * The client terminates the connection without retry

Note: Regardless of validation outcome in an ECH rejection, the client will terminate the current connection. The difference is whether it retries with the new configs (validation success) or treats it as a certificate validation failure (validation failure). Implementers should refer to the state diagram in Appendix A for the complete retry logic flow.

### Backward Compatibility

Clients that do not implement this specification continue to process `retry_configs` as defined in {{!I-D.ietf-tls-esni}}, ignoring the authentication extensions. Servers that do not implement this specification send `retry_configs` as usual.

# Example Exchange

## Initial Setup

Consider `api.example.com` as a service protected by ECH with public name `ech.example.net`. The operator publishes an ECHConfig via DNS HTTPS RR with the `ech_authinfo` extension containing:

- Method: RPK (value 1)
- Trusted keys: SHA-256 hash of an Ed25519 signing key's SPKI

## Successful ECH

This flow works identically to existing ECH

## ECH Rejection with Recovery

1. Client connects: Uses outdated ECHConfig
2. Server rejects ECH: Cannot decrypt inner ClientHello
3. Server continues outer handshake:
   - Sends signed ECHConfig in EncryptedExtensions
   - Uses certificate for `foo.example.net`
4. Client recovery:
   - Validates new ECHConfig
   - Closes connection
   - Immediately retries with new ECHConfig

# Security Considerations {#security}

## Passive Attackers

This mechanism preserves ECH's protection against passive observation. ECHConfig updates are delivered within the EncryptedExtensions TLS message, preventing passive observers from learning about configuration changes. The mechanism ensures that even during retry scenarios, the client's intended server name is never exposed in cleartext.

## Active Network Attackers

The security of this mechanism fundamentally depends on the authenticity of the initial ECHConfig. If an attacker can inject a malicious initial configuration, the client's privacy is compromised, but their connections remain properly authenticated.

Initial retrieval of ECHConfigList via DNS is unchanged by this mechanism. This specification does not attempt to authenticate the initial DNS fetch. ECHConfigs obtained via HTTPS from a well-known URI benefit from Web PKI authentication. Pre-configured ECHConfigs in applications derive their trust from the application's distribution channel.

### Retry Configuration Integrity

ECHConfigs delivered in EncryptedExtensions are usually protected by TLS 1.3's handshake encryption and integrity mechanisms. The Finished message ensures that any modification by an attacker would be detected. The authenticity of the Finished message is assured by validating the server's certificate chain, which the client checks is valid for the ECH Public Name.

However, signed ECHConfigs don't benefit from this authentication because the client does not validate the server's certificate chain. Instead, the client verifies the ECHConfigs against the authenticator provided in the initial ECHConfig. This provides the same level of authenticity as checking the ECH Public Name would.

he inclusion of `not_after` timestamps (for RPK) or certificate validity periods (for PKIX) ensures configuration freshness. These temporal bounds prevent clients from accepting stale configurations that might use compromised keys or otherwise parameters. ECH providers should use a window of 24 hours.

### Key Management

Servers MUST protect their ECH update signing keys. If an RPK signing key is compromised, the server SHOULD remove its hash from `trusted_keys`. Servers SHOULD including multiple keys in `trusted_keys` to facilitate key rotation and recovery from compromise.

For PKIX-based updates, normal certificate lifecycle management applies. Servers SHOULD obtain new certificates before existing ones expire.

## Implementation Vulnerabilities

### Failure Handling

ECH connection attempts with signed updates are handled identically to existing ECH connection attempts. The only difference is in how the server authenticates retry configurations, not how it responds to the success or failure of that authentication.

Algorithm agility is provided through the TLS SignatureScheme registry for RPK and standard PKIX certificate algorithms. Implementations SHOULD support commonly deployed algorithms and MUST be able to handle algorithm transitions.

### Denial of Service Considerations

The ECH Specification allows ECH Operators to decide which ECH extensions to attempt to decrypt based on the public ECHConfig ID advertised in the Client Hello and the public SNI name. This extension reduces the value of that signal, meaning that ECH operators will need to be willing to trial decrypt incoming ECH extensions. This is not a substantial burden, should be accounted for when provisioning these signed configs.

Attackers cannot force servers to send signed ECHConfigs without establishing TLS connections. Standard TLS denial-of-service mitigations (rate limiting, stateless cookies) apply equally to this mechanism.

# Privacy Considerations

This specification introduces no new risks those already present in TLS and DNS when used with ECH.

# IANA Considerations {#iana}

## ECHConfig Extension

IANA is requested to add the following entry to the "ECH Configuration Extension Type Values" registry:

- Extension Name: `ech_authinfo`
- Value: TBD1
- Purpose: Conveys supported authentication methods and trusted keys
- Reference: This document

- Extension Name: `ech_auth`
- Value: TBD2
- Purpose: Conveys authenticator and signatures
- Reference: This document

## X.509 Certificate Extension OID

IANA is requested to allocate an object identifier (OID) under the "SMI Security for PKIX Certificate Extensions (1.3.6.1.5.5.7.1)" registry with the following values:

- OID: id-pe-echConfigSigning (1.3.6.1.5.5.7.1.TBD2)
- Name: ECH Configuration Signing
- Description: Indicates that the certificate's subject public key is authorized to sign ECH configuration updates for the DNS names in the certificate's Subject Alternative Name (SAN).
- Criticality: Certificates containing this extension MUST mark it critical.
- Reference: This document.

## ECH Authentication Methods Registry

IANA is requested to establish a new registry called "ECH Authentication Methods" with the following initial values:

| Value | Method     | Description                                  | Reference      |
|-------|------------|----------------------------------------------|----------------|
| 0     | RPK        | Raw Public Key                               | This document  |
| 1     | PKIX       | X.509 with critical id-pe-echConfigSigning   | This document  |
| 2-255 | Unassigned | -                                            | -              |

New values are assigned via IETF Review.

# Deployment Considerations {#deployment-considerations}

## Method Selection

Operators SHOULD support at least one widely implemented method. PKIX (critical extension) provides easier operational deployment with standard certificate issuance workflows. RPK offers small artifacts and simple verification but must the list of hashed keys and those used for signing must be carefully kept in sync.

## Size Considerations

When sending signed ECHConfigs in EncryptedExtensions, servers should be mindful of message size to avoid fragmentation or exceeding anti-amplification limits. RPK signatures are typically more compact than PKIX certificate chains.

## Key Rotation

Publish updates well in advance of key retirement. Include appropriate validity periods for each method. Consider overlapping validity windows to allow graceful client migration.

# Acknowledgments

The authors thank Martin Thomson for earlier contributions and discussions on the initial draft.

