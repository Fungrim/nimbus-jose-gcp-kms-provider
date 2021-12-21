package io.github.fungrim.nimbus.gcp.kms.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;

import io.github.fungrim.nimbus.gcp.UncheckedJoseException;

public class Algorithms {
    
    private Algorithms() { }

    public static byte[] digest(byte[] cleartext, JWSAlgorithm a) throws JOSEException {
        try {
            MessageDigest md = getDigestForAlgorithm(a);
            md.update(cleartext);
            return md.digest();
        } catch(NoSuchAlgorithmException e) {
            throw new JOSEException(e.getMessage(), e);
        }
    }

    public static boolean isHmac(JWSAlgorithm alg) {
        return JWSAlgorithm.Family.HMAC_SHA.contains(alg);
    }

    public static MessageDigest getDigestForAlgorithm(JWSAlgorithm a) throws NoSuchAlgorithmException {
        String name = a.getName();
        if(name.endsWith("256") || name.endsWith("256K")) {
            return MessageDigest.getInstance("SHA256");
        } else if(name.endsWith("384")) {
            return MessageDigest.getInstance("SHA384");
        } else if(name.endsWith("512")) {
            return MessageDigest.getInstance("SHA512");
        } else {
            throw new NoSuchAlgorithmException("Could not find message digest for algorithm: " + a);
        }
    }

    public static Curve getCurve(CryptoKeyVersion key) throws JOSEException {
        switch(key.getAlgorithm()) {
            case EC_SIGN_P256_SHA256:
                return Curve.P_256;
            case EC_SIGN_P384_SHA384:
                return Curve.P_384;
            case EC_SIGN_SECP256K1_SHA256:
                return Curve.SECP256K1;
            case HMAC_SHA256:
            case RSA_SIGN_PKCS1_2048_SHA256:
            case RSA_SIGN_PKCS1_3072_SHA256:
            case RSA_SIGN_PKCS1_4096_SHA256:
            case RSA_SIGN_PKCS1_4096_SHA512:
            case RSA_SIGN_PSS_2048_SHA256:
            case RSA_SIGN_PSS_3072_SHA256:
            case RSA_SIGN_PSS_4096_SHA256:
            case RSA_SIGN_PSS_4096_SHA512:
            case CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED:
            case EXTERNAL_SYMMETRIC_ENCRYPTION:
            case GOOGLE_SYMMETRIC_ENCRYPTION:
            case RSA_DECRYPT_OAEP_2048_SHA1:
            case RSA_DECRYPT_OAEP_2048_SHA256:
            case RSA_DECRYPT_OAEP_3072_SHA1:
            case RSA_DECRYPT_OAEP_3072_SHA256:
            case RSA_DECRYPT_OAEP_4096_SHA1:
            case RSA_DECRYPT_OAEP_4096_SHA256:
            case RSA_DECRYPT_OAEP_4096_SHA512:
            case UNRECOGNIZED:
            default:
                throw new JOSEException("Key '" + key.getName() + "' has algorithm " + key.getAlgorithm() + " and is not an EC key");
        }
    }

    public static JWSAlgorithm getSigningAlgorithmUnchecked(CryptoKeyVersion key) {
        try {
            return getSigningAlgorithm(key);
        } catch (JOSEException e) {
            throw new UncheckedJoseException(e);
        }
    }

    public static JWSAlgorithm getSigningAlgorithm(CryptoKeyVersion key) throws JOSEException {
        switch(key.getAlgorithm()) {
            case EC_SIGN_P256_SHA256:
                return JWSAlgorithm.ES256;
            case EC_SIGN_P384_SHA384:
                return JWSAlgorithm.ES384;
            case EC_SIGN_SECP256K1_SHA256:
                return JWSAlgorithm.ES256K;
            case HMAC_SHA256:
                return JWSAlgorithm.HS256;
            case RSA_SIGN_PKCS1_2048_SHA256:
                return JWSAlgorithm.RS256;
            case RSA_SIGN_PKCS1_3072_SHA256:
                return JWSAlgorithm.RS256;
            case RSA_SIGN_PKCS1_4096_SHA256:
                return JWSAlgorithm.RS256;
            case RSA_SIGN_PKCS1_4096_SHA512:
                return JWSAlgorithm.RS512;
            case RSA_SIGN_PSS_2048_SHA256:
                return JWSAlgorithm.PS256;
            case RSA_SIGN_PSS_3072_SHA256:
                return JWSAlgorithm.PS256;
            case RSA_SIGN_PSS_4096_SHA256:
                return JWSAlgorithm.PS256;
            case RSA_SIGN_PSS_4096_SHA512:
                return JWSAlgorithm.PS512;
            case CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED:
            case EXTERNAL_SYMMETRIC_ENCRYPTION:
            case GOOGLE_SYMMETRIC_ENCRYPTION:
            case RSA_DECRYPT_OAEP_2048_SHA1:
            case RSA_DECRYPT_OAEP_2048_SHA256:
            case RSA_DECRYPT_OAEP_3072_SHA1:
            case RSA_DECRYPT_OAEP_3072_SHA256:
            case RSA_DECRYPT_OAEP_4096_SHA1:
            case RSA_DECRYPT_OAEP_4096_SHA256:
            case RSA_DECRYPT_OAEP_4096_SHA512:
            case UNRECOGNIZED:
            default:
                throw new JOSEException("Key '" + key.getName() + "' has algorithm " + key.getAlgorithm() + " which is not supported");
        }
    }

    public static Curve getCurve(JWSAlgorithm alg) throws JOSEException {
        if(alg == JWSAlgorithm.ES256) {
            return Curve.P_256;
        } else if(alg == JWSAlgorithm.ES384) {
            return Curve.P_384;
        } else if(alg == JWSAlgorithm.ES256K) {
            return Curve.SECP256K1;
        } else {
            throw new JOSEException("Could not find EC curve for algorithm: " + alg);
        }
    }
}
