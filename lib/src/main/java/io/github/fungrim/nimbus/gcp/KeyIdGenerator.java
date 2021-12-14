package io.github.fungrim.nimbus.gcp;

import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.CryptoKeyVersionName;

@FunctionalInterface
public interface KeyIdGenerator {

    public default String getKeyId(CryptoKeyVersion key) {
        return getKeyId(CryptoKeyVersionName.parse(key.getName()));
    } 
    
    public String getKeyId(CryptoKeyVersionName key);
    
}
