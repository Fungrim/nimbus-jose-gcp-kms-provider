package io.github.fungrim.nimbus.gcp.kms;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import com.google.cloud.kms.v1.CryptoKey;
import com.google.cloud.kms.v1.CryptoKey.CryptoKeyPurpose;
import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionState;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyRingName;
import com.google.cloud.kms.v1.PublicKey;
import com.google.common.base.Preconditions;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;

import io.github.fungrim.nimbus.gcp.KeyDiscriminator;
import io.github.fungrim.nimbus.gcp.KeyIdGenerator;

public class SigningKeyRingAccessor {
 
    private final KeyRingName keyRing;
    private final KeyManagementServiceClient client;
    private final KeyDiscriminator discriminator;
    private final LoadingCache<String, CryptoKeyVersion> cache;
    private final KeyIdGenerator generator;

    public SigningKeyRingAccessor(KeyRingName keyRing, KeyManagementServiceClient client, KeyIdGenerator generator, KeyDiscriminator discriminator, Duration cacheDuration) {
        Preconditions.checkNotNull(client);
        Preconditions.checkNotNull(keyRing);
        Preconditions.checkNotNull(generator);
        Preconditions.checkNotNull(discriminator);
        this.keyRing = keyRing;
        this.generator = generator;
        this.client = client;
        this.discriminator = discriminator;
        this.cache = CacheBuilder.newBuilder()
            .expireAfterAccess(cacheDuration.toMillis(), TimeUnit.MILLISECONDS)
            .build(new CacheLoader<String, CryptoKeyVersion>() {

            @Override
            public CryptoKeyVersion load(String keyId) throws Exception {
                return fetchAll(k -> true, false).stream().filter(k -> generator.getKeyId(k).equals(keyId)).findFirst().orElseThrow(() -> new JOSEException("Key not found: " + keyId));
            }
        });
    }

    public KeyIdGenerator getGenerator() {
        return generator;
    }

    public KeyManagementServiceClient getClient() {
        return client;
    }

    public JWK getPublicKeyJwk(String keyId) throws JOSEException {
        return getPublicKeyJwk(keyId, resolve(keyId));
    }

    public JWK getPublicKeyJwk(String keyId, CryptoKeyVersion key) throws JOSEException {
        PublicKey publicKey = client.getPublicKey(CryptoKeyVersionName.parse(key.getName()));
        byte[] pem = publicKey.getPemBytes().toByteArray();
        return Algorithms.toPublicKeyJWK(key, keyId, pem);
    }

    public JWK getPublicKeyJwk(CryptoKeyVersionName keyName) throws JOSEException {
        verifyKeyRingName(keyName);
        String id = generator.getKeyId(keyName);
        return getPublicKeyJwk(id, resolve(id));
    }

    public CryptoKeyVersion resolve(String keyId) throws JOSEException {
        try {
            return cache.get(keyId);
        } catch (ExecutionException e) {
            throw new JOSEException("Failed to load key", e.getCause());
        }
    }

    public CryptoKeyVersion get(CryptoKeyVersionName keyName) throws JOSEException {
        verifyKeyRingName(keyName);
        return resolve(generator.getKeyId(keyName));
    }

    private void verifyKeyRingName(CryptoKeyVersionName keyName) {
        KeyRingName ring = KeyRingName.of(keyName.getProject(), keyName.getLocation(), keyName.getKeyRing());
        Preconditions.checkArgument(ring.equals(this.keyRing), "Key ring mismatch, expected '" + this.keyRing + "' but supplied key was '" + ring + "'");
    }

    public Optional<CryptoKeyVersionName> fetchLatest(JWSAlgorithm alg) {
        return fetchLatest(k -> {
            try {
                return alg == Algorithms.getSigningAlgorithm(k);
            } catch (JOSEException e) {
                return false;
            }
        });
    }

    public Optional<CryptoKeyVersionName> fetchLatest(KeyDiscriminator filter) {
        CryptoKeyVersionName latestName = null;
        for (CryptoKey key : client.listCryptoKeys(keyRing).iterateAll()) {
            // key.getPrimary()
            CryptoKeyPurpose purpose = key.getPurpose();
            if(purpose == CryptoKeyPurpose.ASYMMETRIC_SIGN || purpose == CryptoKeyPurpose.MAC) {
                for (CryptoKeyVersion version : client.listCryptoKeyVersions(key.getName()).iterateAll()) {
                    CryptoKeyVersionState state = version.getState();
                    if(state == CryptoKeyVersionState.ENABLED && discriminator.accept(version) && filter.accept(version)) {
                        CryptoKeyVersionName name = CryptoKeyVersionName.parse(version.getName());
                        if(latestName == null) {
                            latestName = name;
                            cache.put(generator.getKeyId(name), version);
                        } else if(Integer.parseInt(latestName.getCryptoKeyVersion()) < Integer.parseInt(name.getCryptoKeyVersion())) {
                            latestName = name;
                            cache.put(generator.getKeyId(name), version);
                        }
                    }
                }
            }
        }
        return Optional.ofNullable(latestName);
    }

    public List<CryptoKeyVersion> fetchAll(KeyDiscriminator filter, boolean cacheKeys) {
        List<CryptoKeyVersion> keys = new ArrayList<>(7);
        for (CryptoKey key : client.listCryptoKeys(keyRing).iterateAll()) {
            // key.getPrimary()
            CryptoKeyPurpose purpose = key.getPurpose();
            if(purpose == CryptoKeyPurpose.ASYMMETRIC_SIGN || purpose == CryptoKeyPurpose.MAC) {
                for (CryptoKeyVersion version : client.listCryptoKeyVersions(key.getName()).iterateAll()) {
                    CryptoKeyVersionState state = version.getState();
                    if(state == CryptoKeyVersionState.ENABLED && discriminator.accept(version) && filter.accept(version)) {
                        if(cacheKeys) {
                            cache.put(generator.getKeyId(CryptoKeyVersionName.parse(version.getName())), version);
                        }
                        keys.add(version);
                    }
                }
            }
        }
        return keys;
    }
}
