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
package io.github.fungrim.nimbus.util;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import io.github.fungrim.nimbus.KmsKeyHandle;
import java.util.Optional;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class PublicJwkSetCreatorTest {

    @Test
    public void testCollect() throws JOSEException {
        KmsKeyHandle k1 = Mockito.mock(KmsKeyHandle.class);
        JWK jwk1 = Mockito.mock(JWK.class);
        Mockito.when(jwk1.getKeyID()).thenReturn("k1");
        Mockito.when(k1.getPublicKey()).thenReturn(Optional.of(jwk1));
        KmsKeyHandle k2 = Mockito.mock(KmsKeyHandle.class);
        Mockito.when(k2.getPublicKey()).thenReturn(Optional.empty());
        JWKSet set = PublicJwkSetCreator.of(k1, k2);
        Assertions.assertEquals(1, set.getKeys().size());
        Assertions.assertNotNull(set.getKeyByKeyId("k1"));
    }
}
