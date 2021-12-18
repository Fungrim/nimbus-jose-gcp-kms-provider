package io.github.fungrim.nimbus.gcp.kms.client;

import java.util.stream.Stream;

import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.CryptoKeyVersionName;

import io.github.fungrim.nimbus.gcp.KeyDiscriminator;

public interface KmsServiceClient {

    public boolean macVerify(CryptoKeyVersionName keyName, byte[] signingInput, byte[] signature);

    public byte[] getPublicKeyPem(CryptoKeyVersionName keyName);

    public CryptoKeyVersion getKey(CryptoKeyVersionName keyName);

    public Stream<CryptoKeyVersion> list(KeyDiscriminator disc); 
    
}
