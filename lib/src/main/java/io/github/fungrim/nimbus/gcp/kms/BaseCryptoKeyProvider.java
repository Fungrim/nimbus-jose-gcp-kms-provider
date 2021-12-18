package io.github.fungrim.nimbus.gcp.kms;

import java.util.Collections;

import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.common.base.Preconditions;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.BaseJWSProvider;

import io.github.fungrim.nimbus.gcp.kms.client.KmsServiceClient;

public abstract class BaseCryptoKeyProvider extends BaseJWSProvider {
    
    protected final KmsServiceClient client;
    protected final CryptoKeyVersion key;

    public BaseCryptoKeyProvider(CryptoKeyVersion key, KmsServiceClient client) throws JOSEException {
        super(Collections.singleton(Algorithms.getSigningAlgorithm(key)));
        Preconditions.checkNotNull(client);
        Preconditions.checkNotNull(key);
        this.client = client;
        this.key = key;
    }

    protected JWSAlgorithm extractAndVerifyAlgorithm(JWSHeader header) throws JOSEException {
        JWSAlgorithm alg = header.getAlgorithm();
		if (!supportedJWSAlgorithms().contains(alg)) {
			throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, supportedJWSAlgorithms()));
		}
        return alg;
    }
}
