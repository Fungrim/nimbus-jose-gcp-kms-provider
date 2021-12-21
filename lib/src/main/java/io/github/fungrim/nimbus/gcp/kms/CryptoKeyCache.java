package io.github.fungrim.nimbus.gcp.kms;

import java.security.PublicKey;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;
import java.util.stream.Stream;

import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.cache.RemovalListener;
import com.google.common.cache.RemovalNotification;
import com.google.common.util.concurrent.UncheckedExecutionException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;

import io.github.fungrim.nimbus.gcp.KeyIdGenerator;
import io.github.fungrim.nimbus.gcp.kms.client.KmsServiceClient;
import io.github.fungrim.nimbus.gcp.kms.util.Algorithms;
import io.github.fungrim.nimbus.gcp.kms.util.Keys;

public class CryptoKeyCache {
    
    public static class Entry {
        
        private final CryptoKeyVersion key;
        private final CryptoKeyVersionName keyName;
        private final String keyId;
        private final JWSAlgorithm algorithm;

        // the public key is lazy as it is expensive to create
        private final AtomicReference<PublicKey> publicKey = new AtomicReference<>();

        @VisibleForTesting
        public Entry(CryptoKeyVersion key, CryptoKeyVersionName keyName, String keyId, JWSAlgorithm algorithm) {
            this.key = key;
            this.keyName = keyName;
            this.keyId = keyId;
            this.algorithm = algorithm;
        }

        public JWSAlgorithm getAlgorithm() {
            return algorithm;
        }

        public CryptoKeyVersion getKey() {
            return key;
        }

        public String getKeyId() {
            return keyId;
        }

        public CryptoKeyVersionName getKeyName() {
            return keyName;
        }

        public JWK getPublicKeyJWK(KmsServiceClient client) throws JOSEException {
            return Keys.toPublicKeyJWK(key, keyId, getPublicKey(client));
        }

        public PublicKey getPublicKey(KmsServiceClient client) throws JOSEException {
            PublicKey pk = publicKey.get();
            if(pk == null) {
                byte[] pem = client.getPublicKeyPem(keyName);
                pk = Keys.toPublicKey(key, pem);
                publicKey.set(pk);
            } 
            return pk;
        }
    }

    private final LoadingCache<CryptoKeyVersionName, Entry> entryCache;
    private final ConcurrentHashMap<String, Entry> keyIdCache;
    private final KmsServiceClient client;
    private final KeyIdGenerator idGenerator;

    public CryptoKeyCache(Duration cacheDuration, KmsServiceClient client, KeyIdGenerator idGenerator) {
        Preconditions.checkNotNull(idGenerator);
        Preconditions.checkNotNull(cacheDuration);
        Preconditions.checkNotNull(client);
        this.client = client;
        this.idGenerator = idGenerator;
        // we keep two caches, one for key ID:s and 
        // one for version names, the former is synced with a 
        // removal listener
        this.keyIdCache = new ConcurrentHashMap<>();
        this.entryCache = CacheBuilder.newBuilder()
            .expireAfterAccess(cacheDuration.toMillis(), TimeUnit.MILLISECONDS)
            .removalListener(new RemovalListener<CryptoKeyVersionName, Entry>() {
                
                @Override
                public void onRemoval(RemovalNotification<CryptoKeyVersionName, Entry> notification) {
                    // sync the key ID cache
                    keyIdCache.remove(notification.getValue().getKeyId());
                }
            }).build(new CacheLoader<CryptoKeyVersionName, Entry>() {
                
                @Override
                public Entry load(CryptoKeyVersionName keyName) throws Exception {
                    // load the key from KMS
                    CryptoKeyVersion key = client.getKey(keyName);
                    JWSAlgorithm algorithm = Algorithms.getSigningAlgorithm(key);
                    String keyId = idGenerator.getKeyId(keyName);
                    return new Entry(key, keyName, keyId, algorithm);
                }
            });
    }

    public Optional<Entry> get(CryptoKeyVersionName keyName) throws JOSEException {
        Preconditions.checkNotNull(keyName);
        try {
            return Optional.ofNullable(entryCache.get(keyName));
        } catch (ExecutionException e) {
            // re-throw JOSE, else unchecked
            if(e.getCause() instanceof JOSEException) {
                throw (JOSEException) e.getCause();
            } else {
                throw new UncheckedExecutionException(e);
            }
        }
    }

    public Optional<Entry> find(JWSAlgorithm alg) {
        Preconditions.checkNotNull(alg);
        // unchecked algorithm extract should be OK here since the client 
        // already has filtered the keys
        return client.list(k -> Algorithms.getSigningAlgorithmUnchecked(k).equals(alg))
            .max((a, b) -> Keys.extractVersion(a).compareTo(Keys.extractVersion(b)))
            .map(this::keyToEntry);
    }

    public Optional<Entry> find(String keyId) {
        Preconditions.checkNotNull(keyId);
        Entry entry = keyIdCache.get(keyId);
        if(entry != null) {
            return Optional.of(entry);
        } else {
            return searchForKeyId(keyId).map(this::keyToEntry);
        }
    }

    public Stream<Entry> list(Predicate<CryptoKeyVersion> filter) {
        Preconditions.checkNotNull(filter);
        return client.list(filter)
            .map(this::keyToEntry);
    }

    private Entry keyToEntry(CryptoKeyVersion v) {
        Entry e = new Entry(v, Keys.parseVersionName(v.getName()), idGenerator.getKeyId(v), Algorithms.getSigningAlgorithmUnchecked(v));
        entryCache.put(e.getKeyName(), e);
        keyIdCache.put(e.getKeyId(), e);
        return e;
    }

    @VisibleForTesting
    LoadingCache<CryptoKeyVersionName, Entry> getEntryCache() {
        return entryCache;
    }

    @VisibleForTesting
    ConcurrentHashMap<String, Entry> getKeyIdCache() {
        return keyIdCache;
    }

    private Optional<CryptoKeyVersion> searchForKeyId(String keyId) {
        return client.list(v -> idGenerator.getKeyId(v).equals(keyId)).findFirst();
    }
}
