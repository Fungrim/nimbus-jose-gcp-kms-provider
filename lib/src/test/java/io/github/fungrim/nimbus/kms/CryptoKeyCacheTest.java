package io.github.fungrim.nimbus.kms;

import java.time.Duration;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Stream;

import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm;
import com.google.cloud.kms.v1.CryptoKeyVersionName;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import io.github.fungrim.nimbus.KeyIdGenerator;
import io.github.fungrim.nimbus.kms.client.KmsServiceClient;
import io.github.fungrim.nimbus.kms.generator.Sha256KeyIdGenerator;
import io.github.fungrim.nimbus.kms.util.Keys;

public class CryptoKeyCacheTest {
    
    private static final String KEY_VERSION_NAME = "projects/test/locations/europe/keyRings/testrings/cryptoKeys/test-rsa-sign/cryptoKeyVersions/1";
    
    private final KeyIdGenerator idGenerator = new Sha256KeyIdGenerator();

    @Test
    public void shouldPropagateRemoval() {
        CryptoKeyVersionName name = Keys.parseVersionName(KEY_VERSION_NAME);
        CryptoKeyCache.Entry entry = new CryptoKeyCache.Entry(null, name, idGenerator.getKeyId(name), null); 
        CryptoKeyCache cache = new CryptoKeyCache(Duration.ofDays(1), Mockito.mock(KmsServiceClient.class), idGenerator);
        cache.getEntryCache().put(name, entry);
        cache.getKeyIdCache().put(entry.getKeyId(), entry);
        cache.getEntryCache().invalidate(name);
        Assertions.assertEquals(0,  cache.getKeyIdCache().size());
    }

    @Test
    public void shouldFindKeyFromKeyRing() {
        CryptoKeyVersionName name = Keys.parseVersionName(KEY_VERSION_NAME);
        CryptoKeyVersion key = CryptoKeyVersion.newBuilder().setAlgorithm(CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256).setName(name.toString()).build();
        KmsServiceClient client = Mockito.mock(KmsServiceClient.class);
        Mockito.when(client.list(Mockito.any())).thenAnswer(c -> {
            Predicate<CryptoKeyVersion> filter = c.getArgument(0);
            if(filter.test(key)) {
                return Stream.of(key);
            } else {
                return Stream.of();
            }
        });
        CryptoKeyCache cache = new CryptoKeyCache(Duration.ofDays(1), client, idGenerator);
        Optional<CryptoKeyCache.Entry> entry = cache.find(idGenerator.getKeyId(name));
        Assertions.assertTrue(entry.isPresent());
        Assertions.assertEquals(1,  cache.getKeyIdCache().size());
        Assertions.assertEquals(1,  cache.getEntryCache().size());
    }
}
