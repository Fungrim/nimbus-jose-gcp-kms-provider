package io.github.fungrim.nimbus.gcp.kms;

import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.nimbusds.jose.JOSEException;

public class JcaConversions {
    
    private JcaConversions() { }

    public static String getSignatureAlgorithmName(CryptoKeyVersion key) throws JOSEException {
        switch(key.getAlgorithm()) {
            case EC_SIGN_P256_SHA256:
                return "SHA256withECDSA";
            case EC_SIGN_P384_SHA384:
                return "SHA384withECDSA";
            case EC_SIGN_SECP256K1_SHA256:
                return "SHA512withECDSA";
            case RSA_SIGN_PKCS1_2048_SHA256:
                return "SHA256withRSA";
            case RSA_SIGN_PKCS1_3072_SHA256:
                return "SHA256withRSA";
            case RSA_SIGN_PKCS1_4096_SHA256:
                return "SHA256withRSA";
            case RSA_SIGN_PKCS1_4096_SHA512:
                return "SHA512withRSA";
            case RSA_SIGN_PSS_2048_SHA256:
                return "SHA256withRSA";
            case RSA_SIGN_PSS_3072_SHA256:
                return "SHA256withRSA";
            case RSA_SIGN_PSS_4096_SHA256:
                return "SHA256withRSA";
            case RSA_SIGN_PSS_4096_SHA512:
                return "SHA512withRSA";
            case HMAC_SHA256:
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
                throw new JOSEException("Key '" + key.getName() + "' has algorithm " + key.getAlgorithm() + " and which has no JCA name");
        }
    }
}
