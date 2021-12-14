package io.github.fungrim.nimbus.gcp;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;

public interface KmsKeyHandle {
    
    public String getKeyId();

    public JWSVerifier getVerifier() throws JOSEException;

    public JWSSigner getSigner() throws JOSEException;

    public JWSHeader.Builder createHeaderBuilder() throws JOSEException;

}
