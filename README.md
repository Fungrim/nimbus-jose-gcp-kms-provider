# Google Cloud KMS provider for Nimbus JOSE
This library provides JWS utilities for Nimbus JOSE (https://bitbucket.org/connect2id/nimbus-jose-jwt) on top of Google Cloud KMS. 

## secp256k1 support
Note that the EC curve `secp256k1` was removed from disabled Java 15 by Oracle, and Java 16 by OpenJDK. This library retains
the necesarry code, but it is not well tested. 

* Ref: https://bugs.openjdk.java.net/browse/JDK-8251547
* Ref: https://www.oracle.com/java/technologies/javase/15-relnote-issues.html#JDK-8237219