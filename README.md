# Google Cloud KMS provider for Nimbus JOSE
This library provides JWS utilities for [Nimbus JOSE](https://bitbucket.org/connect2id/nimbus-jose-jwt) on top of Google Cloud KMS. In short you can sign and verify JWS objects backed by keys in GCP KMS.

You create a `KmsKeyHandleFactory` configured with a KMS client and the name of a key ring. You can then query the key ring via the factory for keys represented by `KmsKeyHandle` objects, and in turn can create Numbus signers and verifiers for JWS objects.

* The current version is: **1.0.0**

## Documentation
Published here: https://fungrim.github.io/nimbus-jose-gcp-kms-provider/

## Dependencies
This library depends on the GCP platform version `24.0.0`, Guava `31.0.1-jre` `bcprov-jdk15on:1.68` and `bcpkix-jdk15on:1.68`, and Nimbus JOSE `9.15.2`. 

### Maven

```xml
<dependency>
  <groupId>io.github.fungrim.nimbus</groupId>
  <artifactId>gcp-kms-nimbus-provider</artifactId>
  <version>1.0.0</version>
</dependency>
```

### Gradle

```
implementation 'io.github.fungrim.nimbus:gcp-kms-nimbus-provider:1.0.0'
```
