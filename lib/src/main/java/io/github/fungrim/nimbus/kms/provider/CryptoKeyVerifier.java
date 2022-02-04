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
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.crypto.impl.RSASSA;
import com.nimbusds.jose.util.Base64URL;
import io.github.fungrim.nimbus.kms.CryptoKeyCache;
import io.github.fungrim.nimbus.kms.client.KmsServiceClient;
import io.github.fungrim.nimbus.kms.util.Algorithms;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public class CryptoKeyVerifier extends BaseCryptoKeyProvider implements JWSVerifier {

    public CryptoKeyVerifier(CryptoKeyCache.Entry entry, KmsServiceClient client) throws JOSEException {
        super(entry, client);
    }

    @Override
    public boolean verify(JWSHeader header, byte[] signingInput, Base64URL signature) throws JOSEException {
        JWSAlgorithm alg = extractAndVerifyAlgorithm(header);
        if (Algorithms.isHmac(alg)) {
            CryptoKeyVersionName keyName = entry.getKeyName();
            return client.macVerify(keyName, signingInput, signature.decode());
        } else {
            try {
                byte[] signatureBytes = signature.decode();
                Signature sig = getSignature(alg);
                sig.initVerify(toPublicKey());
                sig.update(signingInput);
                if (JWSAlgorithm.Family.EC.contains(alg)) {
                    if (ECDSA.getSignatureByteArrayLength(header.getAlgorithm()) != signatureBytes.length) {
                        return false; // from Nimbus
                    }
                    byte[] derSignature = ECDSA.transcodeSignatureToDER(signatureBytes);
                    return sig.verify(derSignature);
                } else {
                    return sig.verify(signatureBytes);
                }
            } catch (InvalidKeyException | SignatureException e) {
                throw new JOSEException("Failed to create JCA signature", e);
            }
        }
    }

    private Signature getSignature(JWSAlgorithm alg) throws JOSEException {
        if (JWSAlgorithm.Family.EC.contains(alg)) {
            return ECDSA.getSignerAndVerifier(alg, getJCAContext().getProvider());
        } else {
            return RSASSA.getSignerAndVerifier(alg, getJCAContext().getProvider());
        }
    }

    private PublicKey toPublicKey() throws JOSEException {
        return entry.getPublicKey(client);
    }
}
