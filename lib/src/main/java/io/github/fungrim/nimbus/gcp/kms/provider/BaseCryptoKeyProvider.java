package io.github.fungrim.nimbus.gcp.kms.provider;

import java.util.Collections;

import com.google.common.base.Preconditions;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.BaseJWSProvider;

import io.github.fungrim.nimbus.gcp.kms.CryptoKeyCache.Entry;
import io.github.fungrim.nimbus.gcp.kms.client.KmsServiceClient;

public abstract class BaseCryptoKeyProvider extends BaseJWSProvider {
    
    protected final KmsServiceClient client;
    protected final Entry entry;

    protected BaseCryptoKeyProvider(Entry entry, KmsServiceClient client) throws JOSEException {
        super(Collections.singleton(entry.getAlgorithm()));
        Preconditions.checkNotNull(client);
        Preconditions.checkNotNull(entry);
        this.client = client;
        this.entry = entry;
    }

    protected JWSAlgorithm extractAndVerifyAlgorithm(JWSHeader header) throws JOSEException {
        JWSAlgorithm alg = header.getAlgorithm();
		if (!supportedJWSAlgorithms().contains(alg)) {
			throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, supportedJWSAlgorithms()));
		}
        return alg;
    }
}
