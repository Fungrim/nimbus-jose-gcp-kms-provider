package io.github.fungrim.nimbus.gcp.kms.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

public class Keys {
    
    private Keys() { }

    public static CryptoKeyVersionName parseVersionName(String name) {
        return CryptoKeyVersionName.parse(name);
    }

    public static JWK toPublicKeyJWK(CryptoKeyVersion key, String keyId, byte[] pemBytes) throws JOSEException {
        return toPublicKeyJWK(key, keyId, toPublicKey(key, pemBytes));
    }

    public static PublicKey toPublicKey(CryptoKeyVersion key, byte[] pemBytes) throws JOSEException {
        PemReader reader = new PemReader(new InputStreamReader(new ByteArrayInputStream(pemBytes)));
        try {
            PemObject spki = reader.readPemObject();
            JWSAlgorithm alg = Algorithms.getSigningAlgorithm(key);
            if(JWSAlgorithm.Family.EC.contains(alg)) {
                return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(spki.getContent()));
            } else if (JWSAlgorithm.Family.RSA.contains(alg)) {
                return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(spki.getContent()));
            } else {
                throw new JOSEException("Cannot create public key for algorithm: " + alg);
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new JOSEException("Failed to read pem from byte array", e);
        }
    }

    public static JWK toPublicKeyJWK(CryptoKeyVersion key, String keyId, PublicKey pkey) throws JOSEException {
        JWSAlgorithm alg = Algorithms.getSigningAlgorithm(key);
        if(JWSAlgorithm.Family.EC.contains(alg)) {
            ECPublicKey eckey = (ECPublicKey) pkey;
            return new ECKey.Builder(Algorithms.getCurve(alg), eckey).keyID(keyId).build();
        } else if (JWSAlgorithm.Family.RSA.contains(alg)) {
            RSAPublicKey rsakey = (RSAPublicKey) pkey;
            return new RSAKey.Builder(rsakey).keyID(keyId).build();
        } else {
            throw new JOSEException("Cannot create public key for algorithm: " + alg);
        }
    }

    public static Integer extractVersion(CryptoKeyVersion version) {
        CryptoKeyVersionName name = CryptoKeyVersionName.parse(version.getName());
        return Integer.parseInt(name.getCryptoKeyVersion());
    }
}
