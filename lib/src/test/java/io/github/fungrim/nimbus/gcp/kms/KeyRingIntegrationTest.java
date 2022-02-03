package io.github.fungrim.nimbus.gcp.kms;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyRingName;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.junit.jupiter.api.Assertions;

import io.github.fungrim.nimbus.gcp.KeyIdGenerator;
import io.github.fungrim.nimbus.gcp.KmsKeyHandle;
import io.github.fungrim.nimbus.gcp.KmsKeyHandleFactory;
import io.github.fungrim.nimbus.gcp.kms.generator.Sha256KeyIdGenerator;

public class KeyRingIntegrationTest {
    
    public static void main(String[] args) throws Exception {
        KeyRingName ring = KeyRingName.parse(args[0]);
        KeyIdGenerator gen = new Sha256KeyIdGenerator();
        Predicate<CryptoKeyVersion> filter = (k) -> true;
        try (KeyManagementServiceClient client = KeyManagementServiceClient.create()) {
            KmsKeyHandleFactory provider = KmsKeyHandleFactory.builder(client, ring)
                .withKeyCacheDuration(Duration.ofSeconds(60))
                .withKeyRingFilter(filter)
                .withKeyIdGenerator(gen)
                .build();

            for (KmsKeyHandle h : provider.list().collect(Collectors.toList())) {
                if(h.getAlgorithm() == JWSAlgorithm.ES256K) {
                    continue;
                }
                testSignedJWT(h);
                testSignedJWS(h);
            }
        }
    }

    private static void testSignedJWS(KmsKeyHandle h) throws Exception {
        // sig
        JWSObject jwsObject = new JWSObject(
                h.createHeaderBuilder().build(),
                new Payload("Hello World"));
        // sign
        jwsObject.sign(h.getSigner());
        // parse
        String token = jwsObject.serialize();
        System.out.println("JWS - " + h.getKeyId() + " / " + h.getAlgorithm() + " : " + token);
        System.out.println("JWK - " + h.getPublicKey().map(k -> k.toJSONString()).orElse("n/a"));
        jwsObject = JWSObject.parse(token);
        // check
        Assertions.assertTrue(jwsObject.verify(h.getVerifier()));
    }

    private static void testSignedJWT(KmsKeyHandle h) throws Exception {
        // claims
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .subject("bob")
            .issuer("https://www.google.com")
            .expirationTime(new Date(LocalDateTime.now().plusHours(24).toInstant(ZoneOffset.UTC).toEpochMilli()))
            .build();
        // jwt
        SignedJWT signedJWT = new SignedJWT(
                h.createHeaderBuilder().build(),
                claimsSet);
        signedJWT.sign(h.getSigner());
        // parse
        String token = signedJWT.serialize();
        System.out.println("JWT - " + h.getKeyId() + " / " + h.getAlgorithm() + " : " + token);
        System.out.println("JWK - " + h.getPublicKey().map(k -> k.toJSONString()).orElse("n/a"));
        signedJWT = SignedJWT.parse(token);
        // check
        Assertions.assertTrue(signedJWT.verify(h.getVerifier()));
    }
}
