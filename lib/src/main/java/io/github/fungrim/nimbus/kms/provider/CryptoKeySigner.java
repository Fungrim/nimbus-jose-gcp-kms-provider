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


import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.util.Base64URL;
import io.github.fungrim.nimbus.kms.CryptoKeyCache;
import io.github.fungrim.nimbus.kms.client.KmsServiceClient;
import io.github.fungrim.nimbus.kms.util.Algorithms;

public class CryptoKeySigner extends BaseCryptoKeyProvider implements JWSSigner {

    public CryptoKeySigner(CryptoKeyCache.Entry entry, KmsServiceClient client) throws JOSEException {
        super(entry, client);
    }

    @Override
    public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
        JWSAlgorithm alg = header.getAlgorithm();
        if (!supportedJWSAlgorithms().contains(alg)) {
            throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, supportedJWSAlgorithms()));
        }
        CryptoKeyVersionName keyName = entry.getKeyName();
        if (alg.getName().startsWith("HS")) {
            byte[] byteArray = client.macSign(keyName, signingInput);
            return Base64URL.encode(byteArray);
        } else {
            byte[] digestBytes = Algorithms.digest(signingInput, alg);
            byte[] ciphertext = client.asymmetricSign(keyName, alg, digestBytes);
            if (JWSAlgorithm.Family.EC.contains(alg)) {
                int sigLength = ECDSA.getSignatureByteArrayLength(header.getAlgorithm());
                byte[] jwsSignature = ECDSA.transcodeSignatureToConcat(ciphertext, sigLength);
                return Base64URL.encode(jwsSignature);
            } else {
                return Base64URL.encode(ciphertext);
            }
        }
    }
}
