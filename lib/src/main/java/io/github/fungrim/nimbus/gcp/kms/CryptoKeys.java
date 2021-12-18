package io.github.fungrim.nimbus.gcp.kms;

import com.google.cloud.kms.v1.CryptoKeyVersionName;

public class CryptoKeys {
    
    private CryptoKeys() { }

    public static CryptoKeyVersionName parseVersionName(String name) {
        return CryptoKeyVersionName.parse(name);
    }
}
