package io.github.fungrim.nimbus.gcp;

import com.google.cloud.kms.v1.CryptoKeyVersion;

@FunctionalInterface
public interface KeyDiscriminator {
    
    public boolean accept(CryptoKeyVersion key);

}
