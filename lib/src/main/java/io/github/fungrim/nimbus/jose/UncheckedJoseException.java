package io.github.fungrim.nimbus.jose;

import com.nimbusds.jose.JOSEException;

/**
 * This exception is used for when the code point has already passed
 * places where checked JOSE exceptions has already been thrown. As such, 
 * it is an illegal state and represents a bug or an outdated library. 
 */
public class UncheckedJoseException extends IllegalStateException {
    
    public UncheckedJoseException(JOSEException e) {
        super(e);
    }
}
