package io.github.fungrim.nimbus;

import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.common.base.Preconditions;

/**
 * The ID generator is used to create stable, but obfuscated, JWK
 * key ID:s. The default implementation return a SHA-256 of the KMS
 * resource name. 
 */
@FunctionalInterface
public interface KeyIdGenerator {

    public default String getKeyId(CryptoKeyVersion key) {
        Preconditions.checkNotNull(key);
        return getKeyId(CryptoKeyVersionName.parse(key.getName()));
    } 
    
    public String getKeyId(CryptoKeyVersionName key);
    
}
