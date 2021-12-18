package io.github.fungrim.nimbus.gcp.kms.client;

import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import com.google.cloud.kms.v1.CryptoKey.CryptoKeyPurpose;
import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionState;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyRingName;
import com.google.common.base.Preconditions;
import com.google.protobuf.ByteString;

import io.github.fungrim.nimbus.gcp.KeyDiscriminator;

public class DefaultKmsServiceClient implements KmsServiceClient {
    
    private final KeyRingName keyRing;
    private final KeyDiscriminator keyRingDiscriminator;
    private final KeyManagementServiceClient client;

    public DefaultKmsServiceClient(KeyManagementServiceClient client, KeyRingName keyRing, KeyDiscriminator keyRingDiscriminator) {
        Preconditions.checkNotNull(client);
        Preconditions.checkNotNull(keyRing);
        Preconditions.checkNotNull(keyRingDiscriminator);
        this.keyRingDiscriminator = keyRingDiscriminator;
        this.keyRing = keyRing;
        this.client = client;
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
    public Stream<CryptoKeyVersion> list(KeyDiscriminator disc) {
        return StreamSupport.stream(client.listCryptoKeys(keyRing).iterateAll().spliterator(), false)
                .filter(k -> isPurposeSigning(k.getPurpose()))
                .flatMap(k -> StreamSupport.stream(client.listCryptoKeyVersions(k.getName()).iterateAll().spliterator(), false))
                .filter(v -> v.getState() == CryptoKeyVersionState.ENABLED)
                .filter(keyRingDiscriminator::accept)
                .filter(disc::accept);

    }

    private boolean isPurposeSigning(CryptoKeyPurpose p) {
        return p == CryptoKeyPurpose.ASYMMETRIC_SIGN || p == CryptoKeyPurpose.MAC;
    }
}
