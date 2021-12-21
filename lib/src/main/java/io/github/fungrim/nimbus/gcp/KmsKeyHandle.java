package io.github.fungrim.nimbus.gcp;

import java.util.Optional;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jwk.JWK;

/**
 * This is a representation of a KMS crypto key (with version). Use it
 * to create signers and verifiers for Nimbus JOSE. 
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
     *  Get a signer for JWS signature creation.
     */
    public JWSSigner getSigner() throws JOSEException;

    /**
     * Create a header builder with algorithm and key ID already populated. 
     */
    public JWSHeader.Builder createHeaderBuilder() throws JOSEException;

    /**
     * Get the algorithm this key represents. 
     */
    public JWSAlgorithm getAlgorithm() throws JOSEException;

    /**
     * Get the JCA public key representation of the KMS key, this
     * will return an empty optional for HMAC keys.
     */
    public Optional<JWK> getPublicKey() throws JOSEException;

}
