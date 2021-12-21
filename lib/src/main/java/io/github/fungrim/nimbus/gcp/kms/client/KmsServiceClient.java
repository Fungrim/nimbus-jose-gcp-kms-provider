package io.github.fungrim.nimbus.gcp.kms.client;

import java.util.function.Predicate;
import java.util.stream.Stream;

import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.nimbusds.jose.JWSAlgorithm;

public interface KmsServiceClient {

    public boolean macVerify(CryptoKeyVersionName keyName, byte[] signingInput, byte[] signature);

    public byte[] getPublicKeyPem(CryptoKeyVersionName keyName);

    public CryptoKeyVersion getKey(CryptoKeyVersionName keyName);

    public Stream<CryptoKeyVersion> list(Predicate<CryptoKeyVersion> filter);

    public byte[] macSign(CryptoKeyVersionName keyName, byte[] signingInput);

    public byte[] asymmetricSign(CryptoKeyVersionName keyName, JWSAlgorithm algorithm, byte[] digestBytes); 
    
}
