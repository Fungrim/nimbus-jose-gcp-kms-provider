package io.github.fungrim.nimbus.util;

import java.util.Optional;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import io.github.fungrim.nimbus.KmsKeyHandle;

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
