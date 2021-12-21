package io.github.fungrim.nimbus.gcp.kms.client;

import java.util.function.Predicate;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import com.google.cloud.kms.v1.CryptoKey.CryptoKeyPurpose;
import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionState;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.cloud.kms.v1.Digest;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyRingName;
import com.google.common.base.Preconditions;
import com.google.protobuf.ByteString;
import com.nimbusds.jose.JWSAlgorithm;

public class DefaultKmsServiceClient implements KmsServiceClient {
    
    private final KeyRingName keyRing;
    private final Predicate<CryptoKeyVersion> keyRingFilter;
    private final KeyManagementServiceClient client;

    public DefaultKmsServiceClient(KeyManagementServiceClient client, KeyRingName keyRing, Predicate<CryptoKeyVersion> keyRingFilter) {
        Preconditions.checkNotNull(keyRingFilter);
        Preconditions.checkNotNull(keyRing);
        Preconditions.checkNotNull(client);
        this.keyRingFilter = keyRingFilter;
        this.keyRing = keyRing;
        this.client = client;
    }
    
    @Override
    public byte[] asymmetricSign(CryptoKeyVersionName keyName, JWSAlgorithm algorithm, byte[] digestBytes) {
        return client.asymmetricSign(keyName, createDigest(algorithm, digestBytes)).getSignature().toByteArray();
    }

    @Override
    public byte[] macSign(CryptoKeyVersionName keyName, byte[] signingInput) {
        return client.macSign(keyName, ByteString.copyFrom(signingInput)).getMac().toByteArray();
    }

    @Override
    public byte[] getPublicKeyPem(CryptoKeyVersionName keyName) {
        return client.getPublicKey(keyName).getPemBytes().toByteArray();
    }

    @Override
    public boolean macVerify(CryptoKeyVersionName keyName, byte[] signingInput, byte[] signature) {
        return client.macVerify(keyName, ByteString.copyFrom(signingInput), ByteString.copyFrom(signature)).getSuccess();
    }

    @Override
    public CryptoKeyVersion getKey(CryptoKeyVersionName keyName) {
        return client.getCryptoKeyVersion(keyName);
    }

    @Override
    public Stream<CryptoKeyVersion> list(Predicate<CryptoKeyVersion> filter) {
        return StreamSupport.stream(client.listCryptoKeys(keyRing).iterateAll().spliterator(), false)
                .filter(k -> isPurposeSigning(k.getPurpose()))
                .flatMap(k -> StreamSupport.stream(client.listCryptoKeyVersions(k.getName()).iterateAll().spliterator(), false))
                .filter(v -> v.getState() == CryptoKeyVersionState.ENABLED)
                .filter(keyRingFilter::test)
                .filter(filter::test);

    }

    private boolean isPurposeSigning(CryptoKeyPurpose p) {
        return p == CryptoKeyPurpose.ASYMMETRIC_SIGN || p == CryptoKeyPurpose.MAC;
    }

    private Digest createDigest(JWSAlgorithm alg, byte[] digestBytes) {
        if(alg.getName().endsWith("256") || alg.getName().endsWith("256K")) {
            return Digest.newBuilder().setSha256(ByteString.copyFrom(digestBytes)).build();
        } else if(alg.getName().endsWith("384")) {
            return Digest.newBuilder().setSha384(ByteString.copyFrom(digestBytes)).build();
        } else {
            return Digest.newBuilder().setSha512(ByteString.copyFrom(digestBytes)).build();
        }
    }
}
