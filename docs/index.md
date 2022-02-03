# Google Cloud KMS provider for Nimbus JOSE
This library provides JWS utilities for [Nimbus JOSE](https://bitbucket.org/connect2id/nimbus-jose-jwt) on top of Google Cloud KMS. In short you can sign and verify JWS objects backed by keys in GCP KMS. You create a `KmsKeyHandleFactory` configured with a KMS client and the name of a key ring. You can then query the key ring via the factory for keys represented by `KmsKeyHandle` objects, and in turn can create Nimbus signers and verifiers for JWS objects.

* The current version is: **1.0.0**

## Maven

```xml
<dependency>
  <groupId>io.github.fungrim.nimbus</groupId>
  <artifactId>gcp-kms-nimbus-provider</artifactId>
  <version>1.0.0</version>
</dependency>
```

## Gradle

```
implementation 'io.github.fungrim.nimbus:gcp-kms-nimbus-provider:1.0.0'
```

## Prerequisites

You need to configure the GCP application credentials, e.g.: 

```
export GOOGLE_APPLICATION_CREDENTIALS=my-sa.json
```

Create a key ring if you don't already have one, e.g.: 

```
gcloud kms keyrings create jws-keys --location=us-east1
```

Create at least one key to use, e.g.: 

```
gcloud kms keys create jwd-ec-1 \
   --location=us-east1 \
   --keyring=jws-keys \
   --purpose=asymmetric-signing \
   --default-algorithm=ec-sign-p256-sha256
```

Make sure you, or the SA you're using, have rights to use the keys, for example via the role `roles/cloudkms.signerVerifier` 

## TL;DR

```java
try (KeyManagementServiceClient client = KeyManagementServiceClient.create()) {

    // you need the resource ID of the key ring to use
    String keyRingResourceName = "projects/you-project/locations/europe/keyRings/your-keyring";
    
    // the key handle factory is your key access point, and caches keys in memory for you
    KmsKeyHandleFactory factory = KmsKeyHandleFactory.builder(client, KeyRingName.parse(keyRingResourceName))
                    .withKeyCacheDuration(Duration.ofSeconds(60))
                    .build();

    // there's several ways of getting hold of a key, for example
    // by a key version resource name, but below we don't care and ask
    // for a key by algorithm - the provider will pick the a matching key and
    // the latest version
    KmsKeyHandle handle = factory.find(JWSAlgorithm.ES256);

    // create claims
    JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .subject("bob")
            .issuer("https://www.google.com")
            .expirationTime(new Date(LocalDateTime.now().plusHours(24).toInstant(ZoneOffset.UTC).toEpochMilli()))
            .build();

    // let the handle create the header, this will set the algorithm and key ID automagically
    JWSHeader header = handle.createHeaderBuilder().build();

    // create and sign 
    SignedJWT jwt = new SignedJWT(header, claims);
    jwt.sign(handler.getSigner());

    // verify
    String token = jwt.serialize();
    SignedJWT parsed = SignedJWT.parse(token);
    if(!partsed.verify(handler.getVerifier())) {
        System.out.println("Help! Help! I'm being repressed!");
    }
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
