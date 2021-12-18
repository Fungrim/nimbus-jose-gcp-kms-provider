package io.github.fungrim.nimbus.gcp.kms;

import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.cache.RemovalListener;
import com.google.common.cache.RemovalNotification;

import io.github.fungrim.nimbus.gcp.KeyIdGenerator;
import io.github.fungrim.nimbus.gcp.kms.client.KmsServiceClient;

public class CryptoKeyCache {
    
    public static class Entry {
        
        private final CryptoKeyVersion key;
        private final CryptoKeyVersionName keyName;
        private final String keyId;

        public Entry(CryptoKeyVersion key, CryptoKeyVersionName keyName, String keyId) {
            this.key = key;
            this.keyName = keyName;
            this.keyId = keyId;
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
        this.keyIdCache = new ConcurrentHashMap<>();
        this.entryCache = CacheBuilder.newBuilder()
            .expireAfterAccess(cacheDuration.toMillis(), TimeUnit.MILLISECONDS)
            .removalListener(new RemovalListener<CryptoKeyVersionName, Entry>() {
                
                @Override
                public void onRemoval(RemovalNotification<CryptoKeyVersionName, Entry> notification) {
                    keyIdCache.remove(notification.getValue().getKeyId());
                }
            }).build(new CacheLoader<CryptoKeyVersionName, Entry>() {
                
                @Override
                public Entry load(CryptoKeyVersionName keyName) throws Exception {
                    CryptoKeyVersion key = client.getKey(keyName);
                    return new Entry(key, keyName, idGenerator.getKeyId(keyName));
                }
            });
    }

    public Optional<Entry> find(String keyId) {
        Preconditions.checkNotNull(keyId);
        Entry entry = keyIdCache.get(keyId);
        if(entry != null) {
            return Optional.of(entry);
        } else {
            return searchForKeyId(keyId)
                .map(v -> {
                    Entry e = new Entry(v, CryptoKeys.parseVersionName(v.getName()), idGenerator.getKeyId(v));
                    entryCache.put(e.getKeyName(), e);
                    keyIdCache.put(e.getKeyId(), e);
                    return e;
                });
        }
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
