package io.github.fungrim.nimbus.gcp.kms;

import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import io.github.fungrim.nimbus.gcp.kms.client.KmsServiceClient;

public class BaseCryptoKeyProviderTest {
    
    private static class Provider extends BaseCryptoKeyProvider {

        public Provider(CryptoKeyVersion key, KmsServiceClient client) throws JOSEException {
            super(key, client);
        }
    }

    @Test
    public void shouldThrowOnUnsupportedAlgorithm() throws Exception {
        CryptoKeyVersion k = CryptoKeyVersion.newBuilder().setAlgorithm(CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256).build();
        KmsServiceClient c = Mockito.mock(KmsServiceClient.class);
        Assertions.assertThrows(JOSEException.class, () -> {
            new Provider(k, c).extractAndVerifyAlgorithm(new JWSHeader(JWSAlgorithm.PS256));
        });
    }
}
