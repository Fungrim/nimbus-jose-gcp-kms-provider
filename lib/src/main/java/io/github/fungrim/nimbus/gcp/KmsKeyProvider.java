package io.github.fungrim.nimbus.gcp;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyRingName;
import com.google.common.base.Preconditions;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

import io.github.fungrim.nimbus.gcp.kms.CryptoKeySigner;
import io.github.fungrim.nimbus.gcp.kms.CryptoKeyVerifier;
import io.github.fungrim.nimbus.gcp.kms.JwsConversions;
import io.github.fungrim.nimbus.gcp.kms.Sha256KeyIdGenerator;
import io.github.fungrim.nimbus.gcp.kms.SigningKeyRingAccessor;

public class KmsKeyProvider {

    public static class Builder {

        private KeyManagementServiceClient client;
        private KeyDiscriminator disc;
        private KeyIdGenerator gen;
        private Duration dur;
        private KeyRingName keyRing;

        private Builder(KeyManagementServiceClient client, KeyRingName keyRing) {
            this.client = client;
            this.keyRing = keyRing;
        }

        public Builder withKeyDiscriminator(KeyDiscriminator disc) {
            this.disc = disc;
            return this;
        }

        public Builder withKeyIdGenerator(KeyIdGenerator gen) {
            this.gen = gen;
            return this;
        }

        public Builder withKeyCacheDuration(Duration dur) {
            this.dur = dur;
            return this;
        }

        public KmsKeyProvider build() throws JOSEException {
            KeyDiscriminator discriminator = disc == null ? k -> true : disc;
            KeyIdGenerator generator = gen == null ? new Sha256KeyIdGenerator() : gen;
            Duration duration = dur == null ? Duration.ofMinutes(60) : dur;
            SigningKeyRingAccessor accessor = new SigningKeyRingAccessor(keyRing, client, generator, discriminator, duration);
            return new KmsKeyProvider(accessor);
        }
    } 

    public static Builder builder(KeyManagementServiceClient client, KeyRingName keyRing) {
        Preconditions.checkNotNull(client);
        Preconditions.checkNotNull(keyRing);
        return new Builder(client, keyRing);
    }

    private SigningKeyRingAccessor accessor;

    private KmsKeyProvider(SigningKeyRingAccessor accessor) {
        this.accessor = accessor;
    }
 
    public KmsKeyHandle get(CryptoKeyVersionName name) throws JOSEException {
        Preconditions.checkNotNull(name);
        CryptoKeyVersion key = accessor.get(name);
        return new Handle(accessor.getGenerator().getKeyId(key), key);
    }

    public KmsKeyHandle get(String keyId) throws JOSEException {
        Preconditions.checkNotNull(keyId);
        CryptoKeyVersion key = accessor.resolve(keyId);
        return new Handle(accessor.getGenerator().getKeyId(key), key);
    }

    public Optional<KmsKeyHandle> find(JWSAlgorithm alg) throws JOSEException {
        Preconditions.checkNotNull(alg);
        Optional<CryptoKeyVersionName> opt = accessor.fetchLatest(alg);
        return toHandle(opt);
    }

    public Optional<KmsKeyHandle> find(KeyDiscriminator filter) throws JOSEException {
        Preconditions.checkNotNull(filter);
        Optional<CryptoKeyVersionName> opt = accessor.fetchLatest(filter);
        return toHandle(opt);
    }

    private Optional<KmsKeyHandle> toHandle(Optional<CryptoKeyVersionName> opt) throws JOSEException {
        if(opt.isEmpty()) {
            return Optional.empty();
        } else {
            CryptoKeyVersion k = accessor.get(opt.get());
            return Optional.of(new Handle(accessor.getGenerator().getKeyId(k), k));
        }
    }

    public JWKSet getAll() throws JOSEException {
        return getAll(k -> true);
    }

    public JWKSet getAll(KeyDiscriminator filter) throws JOSEException {
        Preconditions.checkNotNull(filter);
        List<JWK> list = new ArrayList<>();
        for (CryptoKeyVersion v : accessor.fetchAll(filter, true)) {
            list.add(accessor.getPublicKeyJwk(accessor.getGenerator().getKeyId(v), v));
        }
        return new JWKSet(list);
    }

    private class Handle implements KmsKeyHandle {

        private final String id;
        private final CryptoKeyVersion key;
    
        private Handle(String id, CryptoKeyVersion key) {
            this.id = id;
            this.key = key;
        }

        @Override
        public String getKeyId() {
            return id;
        }

        @Override
        public JWSSigner getSigner() throws JOSEException {
            return new CryptoKeySigner(key, accessor.getClient());
        }

        @Override
        public JWSVerifier getVerifier() throws JOSEException {
            return new CryptoKeyVerifier(key, accessor.getClient());
        }

        @Override
        public JWSHeader.Builder createHeaderBuilder() throws JOSEException {
            return new JWSHeader.Builder(JwsConversions.getSigningAlgorithm(key)).keyID(id);
        }
    }
}
