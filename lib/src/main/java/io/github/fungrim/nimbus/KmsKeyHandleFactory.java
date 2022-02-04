/**
 * Copyright 2022 Lars J. Nilsson
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.github.fungrim.nimbus;


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
import io.github.fungrim.nimbus.kms.CryptoKeyCache;
import io.github.fungrim.nimbus.kms.CryptoKeyCache.Entry;
import io.github.fungrim.nimbus.kms.client.DefaultKmsServiceClient;
import io.github.fungrim.nimbus.kms.client.KmsServiceClient;
import io.github.fungrim.nimbus.kms.generator.Sha256KeyIdGenerator;
import io.github.fungrim.nimbus.kms.provider.CryptoKeySigner;
import io.github.fungrim.nimbus.kms.provider.CryptoKeyVerifier;
import java.time.Duration;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Stream;

/**
 * This is the main key accessor for the KMS providers. Create a new factory
 * using a {@link Builder}. You need to provide the underlying Google library
 * yourself, including authentication.
 * 
 * <p>
 * This factory operates on a single key ring, which is mandatory when creating
 * the provider.
 * 
 * <p>
 * Disabled KMS keys, and keys that does not support signing will automatically
 * be fitlered out.
 * 
 * <p>
 * The factory will cache KMS keys and associated meta-data. The default cache
 * duration is 60 minutes.
 * 
 * <p>
 * By default, JWT key ID:s will be generated using SHA-256 over the KMS key
 * version resource name.
 */
public class KmsKeyHandleFactory {

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

        /**
         * Use a global key ring filter. This will be applied to all KMS accesses and
         * can be used to pre-emptively filter out keys that should not be used.
         * 
         * <p>
         * By default, no keys are filtered out.
         * 
         * <p>
         * Note that disabled KMS keys, and keys that does not support signing will
         * automatically be fitlered out without the need for a specialised filter.
         */
        public Builder withKeyRingFilter(Predicate<CryptoKeyVersion> disc) {
            this.disc = disc;
            return this;
        }

        /**
         * Set a custom key ID generator. The default generator will use SHA-256 over
         * the KMS key version resource name.
         */
        public Builder withKeyIdGenerator(KeyIdGenerator gen) {
            this.gen = gen;
            return this;
        }

        /**
         * Specify the key cache duration. The default is 60 minutes.
         */
        public Builder withKeyCacheDuration(Duration dur) {
            this.dur = dur;
            return this;
        }

        /**
         * Build the factory.
         */
        public KmsKeyHandleFactory build() throws JOSEException {
            Predicate<CryptoKeyVersion> filter = disc == null ? k -> true : disc;
            KeyIdGenerator generator = gen == null ? new Sha256KeyIdGenerator() : gen;
            Duration duration = dur == null ? Duration.ofMinutes(60) : dur;
            KmsServiceClient kmsClient = new DefaultKmsServiceClient(client, keyRing, filter);
            CryptoKeyCache cache = new CryptoKeyCache(duration, kmsClient, generator);
            return new KmsKeyHandleFactory(kmsClient, cache);
        }
    }

    /**
     * Create a new builder, none of the arguments may be null.
     */
    public static Builder builder(KeyManagementServiceClient client, KeyRingName keyRing) {
        Preconditions.checkNotNull(client);
        Preconditions.checkNotNull(keyRing);
        return new Builder(client, keyRing);
    }

    private final KmsServiceClient client;
    private final CryptoKeyCache cache;

    private KmsKeyHandleFactory(KmsServiceClient client, CryptoKeyCache cache) {
        this.client = client;
        this.cache = cache;
    }

    /**
     * Get a key by name. If the key is not a signing key this method will throw an
     * exception.
     */
    public Optional<KmsKeyHandle> get(CryptoKeyVersionName name) throws JOSEException {
        Preconditions.checkNotNull(name);
        return cache.get(name).map(this::toHandle);
    }

    /**
     * Get a key by JWT ID.
     */
    public Optional<KmsKeyHandle> get(String keyId) throws JOSEException {
        Preconditions.checkNotNull(keyId);
        return cache.find(keyId).map(this::toHandle);
    }

    /**
     * Get a key for a given algorithm. If there are multiple elegible keys for the
     * algorithm, the first returned by the KMS client will be used. Only the latest
     * version of a key will be returned.
     */
    public Optional<KmsKeyHandle> find(JWSAlgorithm alg) throws JOSEException {
        Preconditions.checkNotNull(alg);
        return cache.find(alg).map(this::toHandle);
    }

    /**
     * List all keys.
     */
    public Stream<KmsKeyHandle> list() throws JOSEException {
        return list(k -> true);
    }

    /**
     * List all keys given a key version filter.
     * 
     * @deprecated Use {@link #listByKeyVersion(Predicate)} instead
     */
    @Deprecated
    public Stream<KmsKeyHandle> list(Predicate<CryptoKeyVersion> filter) throws JOSEException {
        return listByKeyVersion(filter);
    }

    /**
     * List all keys given a key version filter.
     */
    public Stream<KmsKeyHandle> listByKeyVersion(Predicate<CryptoKeyVersion> filter) throws JOSEException {
        Preconditions.checkNotNull(filter);
        return cache.listByKeyVersion(filter).map(this::toHandle);
    }

    /**
     * List all keys given an algorithm filter.
     */
    public Stream<KmsKeyHandle> listByAlgorithm(Predicate<JWSAlgorithm> filter) throws JOSEException {
        Preconditions.checkNotNull(filter);
        return cache.listByAlgorithm(filter).map(this::toHandle);
    }

    /// --- PRIVATE --- ///

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
        public JWSAlgorithm getAlgorithm() {
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

        @Override
        public boolean hasPublicKey() {
            return !JWSAlgorithm.Family.HMAC_SHA.contains(getAlgorithm());
        }
    }
}
