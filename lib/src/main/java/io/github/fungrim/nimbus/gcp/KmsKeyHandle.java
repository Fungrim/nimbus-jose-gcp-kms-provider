package io.github.fungrim.nimbus.gcp;

import java.util.Optional;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jwk.JWK;

public interface KmsKeyHandle {
    
    public String getKeyId();

    public JWSVerifier getVerifier() throws JOSEException;

    public JWSSigner getSigner() throws JOSEException;

    public JWSHeader.Builder createHeaderBuilder() throws JOSEException;

    public JWSAlgorithm getAlgorithm() throws JOSEException;

    public Optional<JWK> getPublicKey() throws JOSEException;

}
