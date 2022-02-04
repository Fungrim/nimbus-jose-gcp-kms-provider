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
package io.github.fungrim.nimbus.kms;


import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.nimbusds.jose.JWSAlgorithm;
import io.github.fungrim.nimbus.KeyIdGenerator;
import io.github.fungrim.nimbus.kms.client.KmsServiceClient;
import io.github.fungrim.nimbus.kms.generator.Sha256KeyIdGenerator;
import io.github.fungrim.nimbus.kms.util.Keys;
import java.time.Duration;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class CryptoKeyCacheTest {

    private static final String KEY_VERSION_NAME = "projects/test/locations/europe/keyRings/testrings/cryptoKeys/test-rsa-sign/cryptoKeyVersions/1";

    private final KeyIdGenerator idGenerator = new Sha256KeyIdGenerator();

    @Test
    public void shouldPropagateRemoval() {
        CryptoKeyVersionName name = Keys.parseVersionName(KEY_VERSION_NAME);
        CryptoKeyCache.Entry entry = new CryptoKeyCache.Entry(null, name, idGenerator.getKeyId(name), null);
        CryptoKeyCache cache = new CryptoKeyCache(Duration.ofDays(1), Mockito.mock(KmsServiceClient.class),
                idGenerator);
        cache.getEntryCache().put(name, entry);
        cache.getKeyIdCache().put(entry.getKeyId(), entry);
        cache.getEntryCache().invalidate(name);
        Assertions.assertEquals(0, cache.getKeyIdCache().size());
    }

    @Test
    public void shouldFindKeyFromKeyRing() {
        CryptoKeyVersionName name = Keys.parseVersionName(KEY_VERSION_NAME);
        KmsServiceClient client = createClientWithSingleKey(name, CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256);
        CryptoKeyCache cache = new CryptoKeyCache(Duration.ofDays(1), client, idGenerator);
        Optional<CryptoKeyCache.Entry> entry = cache.find(idGenerator.getKeyId(name));
        Assertions.assertTrue(entry.isPresent());
        Assertions.assertEquals(1, cache.getKeyIdCache().size());
        Assertions.assertEquals(1, cache.getEntryCache().size());
    }

    private KmsServiceClient createClientWithSingleKey(CryptoKeyVersionName name,
            CryptoKeyVersionAlgorithm keyVersion) {
        CryptoKeyVersion key = CryptoKeyVersion.newBuilder().setAlgorithm(keyVersion).setName(name.toString()).build();
        KmsServiceClient client = Mockito.mock(KmsServiceClient.class);
        Mockito.when(client.list(Mockito.any())).thenAnswer(c -> {
            Predicate<CryptoKeyVersion> filter = c.getArgument(0);
            if (filter.test(key)) {
                return Stream.of(key);
            } else {
                return Stream.of();
            }
        });
        return client;
    }

    @Test
    public void shouldListByAlgorithm() {
        CryptoKeyVersionName name = Keys.parseVersionName(KEY_VERSION_NAME);
        KmsServiceClient client = createClientWithSingleKey(name, CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256);
        CryptoKeyCache cache = new CryptoKeyCache(Duration.ofDays(1), client, idGenerator);
        Assertions.assertEquals(1L, cache.listByAlgorithm(a -> a.equals(JWSAlgorithm.ES256)).count());
        Assertions.assertEquals(0L, cache.listByAlgorithm(a -> a.equals(JWSAlgorithm.ES384)).count());
    }

    @Test
    public void shouldListByKeyVersion() {
        CryptoKeyVersionName name = Keys.parseVersionName(KEY_VERSION_NAME);
        KmsServiceClient client = createClientWithSingleKey(name, CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256);
        CryptoKeyCache cache = new CryptoKeyCache(Duration.ofDays(1), client, idGenerator);
        Assertions.assertEquals(1L, cache.listByKeyVersion(v -> v.getName().equals(KEY_VERSION_NAME)).count());
        Assertions.assertEquals(0L, cache.listByKeyVersion(v -> v.getName().equals("dummy")).count());
    }
}
