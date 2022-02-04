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


import com.google.common.base.Preconditions;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.BaseJWSProvider;
import io.github.fungrim.nimbus.kms.CryptoKeyCache;
import io.github.fungrim.nimbus.kms.client.KmsServiceClient;
import java.util.Collections;

public abstract class BaseCryptoKeyProvider extends BaseJWSProvider {

    protected final KmsServiceClient client;
    protected final CryptoKeyCache.Entry entry;

    protected BaseCryptoKeyProvider(CryptoKeyCache.Entry entry, KmsServiceClient client) throws JOSEException {
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
