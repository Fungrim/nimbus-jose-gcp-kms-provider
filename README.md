# Google Cloud KMS provider for Nimbus JOSE
This library provides JWS utilities for [Nimbus JOSE](https://bitbucket.org/connect2id/nimbus-jose-jwt) on top of Google Cloud KMS. In short you can sign and verify JWS objects backed by keys in GCP KMS.

## TL;DR

```java
KeyManagementServiceClient client = ... // you create your own client
String keyRingResourceName = ... // this library operates on a single key ring
KmsKeyProvider provider = KmsKeyProvider.builder(client, KeyRingName.parse(keyRingResourceName))
                .withKeyCacheDuration(Duration.ofSeconds(60))
                .build();

// there's several ways of getting hold of a key, for example
// by a key version resource name, but below we don't care and ask
// for a key by algorithm - the provider will pick the a matching key and
// the latest version
KmsKeyHandle handle = provider.find(JWSAlgorithm.ES256);

JWTClaimsSet claims = // ... create claims

// let the handle create the header, this will set
// the algorithm and key ID
JWSHeader header = handle.createHeaderBuilder().build();

// create and sign 
SignedJWT jwt = new SignedJWT(header, claims);
jwt.sign(handler.getSigner());

// you can of course parse and verify
String token = jwt.serialize();
SignedJWT parsed = SignedJWT.parse(token);
if(!partsed.verify(handler.getVerifier())) {
  // help! help!
}
```

## Algorithm support
All keys for asymmetric signing in GCP KMS are supported - with the exception of `secp256k1`, see below - as well as HMAC signing. 

* EC P256 / SHA256
* EC P384 / SHA384
* EC secp256k1 / SHA256 (see below)
* RSA 2048 PKCS#1 / SHA256
* RSA 3072 PKCS#1 / SHA256
* RSA 4096 PKCS#1 / SHA256
* RSA 4096 PKCS#1 / SHA512
* RSA 2048 PSS / SHA256
* RSA 3072 PSS / SHA256
* RSA 4096 PSS / SHA256
* RSA 4096 PSS / SHA512
* HMAC / SHA256

### secp256k1
Note that the EC curve `secp256k1` was removed from Java 15 by Oracle, and Java 16 by OpenJDK. This library retains
the necesarry code, but it is not well tested. 

* Ref: https://bugs.openjdk.java.net/browse/JDK-8251547
* Ref: https://www.oracle.com/java/technologies/javase/15-relnote-issues.html#JDK-8237219
