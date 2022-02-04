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
package io.github.fungrim.nimbus;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jwk.JWK;
import java.util.Optional;

/**
 * This is a representation of a KMS crypto key (with version). Use it to create
 * signers and verifiers for Nimbus JOSE.
 */
public interface KmsKeyHandle {

    /**
     * Get the key ID. This is a determinable represetation created by a
     * {@link KeyIdGenerator}.
     */
    public String getKeyId();

    /**
     * Get a verified for JWS signature verification.
     */
    public JWSVerifier getVerifier() throws JOSEException;

    /**
     * Get a signer for JWS signature creation.
     */
    public JWSSigner getSigner() throws JOSEException;

    /**
     * Create a header builder with algorithm and key ID already populated.
     */
    public JWSHeader.Builder createHeaderBuilder() throws JOSEException;

    /**
     * Get the algorithm this key represents.
     */
    public JWSAlgorithm getAlgorithm();

    /**
     * Get the JCA public key representation of the KMS key, this will return an
     * empty optional for HMAC keys.
     */
    public Optional<JWK> getPublicKey() throws JOSEException;

    /**
     * Checks if the key has a public JCA representation, this will return false for
     * HMAC keys.
     */
    public boolean hasPublicKey();

}
