package io.github.fungrim.nimbus.gcp.kms.provider;

import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import io.github.fungrim.nimbus.gcp.kms.CryptoKeyCache.Entry;
import io.github.fungrim.nimbus.gcp.kms.client.KmsServiceClient;
import io.github.fungrim.nimbus.gcp.kms.util.Algorithms;

public class BaseCryptoKeyProviderTest {
    
    private static class Provider extends BaseCryptoKeyProvider {

        public Provider(Entry entry, KmsServiceClient client) throws JOSEException {
            super(entry, client);
        }
    }

    @Test
    public void shouldThrowOnUnsupportedAlgorithm() throws Exception {
        KmsServiceClient c = Mockito.mock(KmsServiceClient.class);
        Entry e = Mockito.mock(Entry.class);
        CryptoKeyVersion k = CryptoKeyVersion.newBuilder().setAlgorithm(CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256).build();
        Mockito.when(e.getAlgorithm()).thenReturn(Algorithms.getSigningAlgorithm(k));
        Assertions.assertThrows(JOSEException.class, () -> {
            new Provider(e, c).extractAndVerifyAlgorithm(new JWSHeader(JWSAlgorithm.PS256));
        });
    }
}
