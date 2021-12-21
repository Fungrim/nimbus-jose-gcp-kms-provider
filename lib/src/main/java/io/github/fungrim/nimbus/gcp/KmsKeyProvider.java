package io.github.fungrim.nimbus.gcp;

import java.time.Duration;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Stream;

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

import io.github.fungrim.nimbus.gcp.kms.CryptoKeyCache;
import io.github.fungrim.nimbus.gcp.kms.CryptoKeyCache.Entry;
import io.github.fungrim.nimbus.gcp.kms.client.DefaultKmsServiceClient;
import io.github.fungrim.nimbus.gcp.kms.client.KmsServiceClient;
import io.github.fungrim.nimbus.gcp.kms.generator.Sha256KeyIdGenerator;
import io.github.fungrim.nimbus.gcp.kms.provider.CryptoKeySigner;
import io.github.fungrim.nimbus.gcp.kms.provider.CryptoKeyVerifier;

public class KmsKeyProvider {

    public static class Builder {

        private KeyManagementServiceClient client;
        private Predicate<CryptoKeyVersion> disc;
        private KeyIdGenerator gen;
        private Duration dur;
        private KeyRingName keyRing;

        private Builder(KeyManagementServiceClient client, KeyRingName keyRing) {
            this.client = client;
            this.keyRing = keyRing;
        }

        public Builder withKeyRingFilter(Predicate<CryptoKeyVersion> disc) {
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
            Predicate<CryptoKeyVersion> filter = disc == null ? k -> true : disc;
            KeyIdGenerator generator = gen == null ? new Sha256KeyIdGenerator() : gen;
            Duration duration = dur == null ? Duration.ofMinutes(60) : dur;
            KmsServiceClient kmsClient = new DefaultKmsServiceClient(client, keyRing, filter);
            CryptoKeyCache cache = new CryptoKeyCache(duration, kmsClient, generator);
            return new KmsKeyProvider(kmsClient, cache);
        }
    } 

    public static Builder builder(KeyManagementServiceClient client, KeyRingName keyRing) {
        Preconditions.checkNotNull(client);
        Preconditions.checkNotNull(keyRing);
        return new Builder(client, keyRing);
    }

    private final KmsServiceClient client;
    private final CryptoKeyCache cache;

    private KmsKeyProvider(
            KmsServiceClient client, 
            CryptoKeyCache cache) {
        this.client = client;
        this.cache = cache;
    }
 
    public Optional<KmsKeyHandle> get(CryptoKeyVersionName name) throws JOSEException {
        Preconditions.checkNotNull(name);
        return cache.get(name).map(this::toHandle);
    }

    public Optional<KmsKeyHandle> get(String keyId) throws JOSEException {
        Preconditions.checkNotNull(keyId);
        return cache.find(keyId).map(this::toHandle);
    }

    public Optional<KmsKeyHandle> find(JWSAlgorithm alg) throws JOSEException {
        Preconditions.checkNotNull(alg);
        return cache.find(alg).map(this::toHandle);
    }

    public Stream<KmsKeyHandle> list() throws JOSEException {
        return list(k -> true);
    }

    public Stream<KmsKeyHandle> list(Predicate<CryptoKeyVersion> filter) throws JOSEException {
        Preconditions.checkNotNull(filter);
        return cache.list(filter).map(this::toHandle);
    }

    private KmsKeyHandle toHandle(Entry e) {
        return new Handle(e);
    }
    private class Handle implements KmsKeyHandle {

        private final Entry entry;
    
        private Handle(Entry entry) {
            this.entry = entry;
        }

        @Override
        public String getKeyId() {
            return entry.getKeyId();
        }

        @Override
        public JWSAlgorithm getAlgorithm() throws JOSEException {
            return entry.getAlgorithm();
        }

        @Override
        public JWSSigner getSigner() throws JOSEException {
            return new CryptoKeySigner(entry, client);
        }

        @Override
        public JWSVerifier getVerifier() throws JOSEException {
            return new CryptoKeyVerifier(entry, client);
        }

        @Override
        public JWSHeader.Builder createHeaderBuilder() throws JOSEException {
            return new JWSHeader.Builder(getAlgorithm()).keyID(entry.getKeyId());
        }

        @Override
        public Optional<JWK> getPublicKey() throws JOSEException {
            return JWSAlgorithm.Family.HMAC_SHA.contains(getAlgorithm()) 
                        ? Optional.empty() 
                        : Optional.of(entry.getPublicKeyJWK(client));
        }
    }
}
