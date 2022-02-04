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
package io.github.fungrim.nimbus.kms.provider;


import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import io.github.fungrim.nimbus.kms.CryptoKeyCache;
import io.github.fungrim.nimbus.kms.client.KmsServiceClient;
import io.github.fungrim.nimbus.kms.util.Algorithms;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class BaseCryptoKeyProviderTest {

    private static class Provider extends BaseCryptoKeyProvider {

        public Provider(CryptoKeyCache.Entry entry, KmsServiceClient client) throws JOSEException {
            super(entry, client);
        }
    }

    @Test
    public void shouldThrowOnUnsupportedAlgorithm() throws Exception {
        KmsServiceClient c = Mockito.mock(KmsServiceClient.class);
        CryptoKeyCache.Entry e = Mockito.mock(CryptoKeyCache.Entry.class);
        CryptoKeyVersion k = CryptoKeyVersion.newBuilder().setAlgorithm(CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256)
                .build();
        Mockito.when(e.getAlgorithm()).thenReturn(Algorithms.getSigningAlgorithm(k));
        Assertions.assertThrows(JOSEException.class, () -> {
            new Provider(e, c).extractAndVerifyAlgorithm(new JWSHeader(JWSAlgorithm.PS256));
        });
    }
}
