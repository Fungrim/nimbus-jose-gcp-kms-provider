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
package io.github.fungrim.nimbus.gcp.kms;


import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyRingName;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.github.fungrim.nimbus.KeyIdGenerator;
import io.github.fungrim.nimbus.KmsKeyHandle;
import io.github.fungrim.nimbus.KmsKeyHandleFactory;
import io.github.fungrim.nimbus.kms.generator.Sha256KeyIdGenerator;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * This integration test must be run manually with a GCP application
 * credentials. It also needs a key ring with one or more keys to test with. Run
 * it with the resource ID of the key ring as a program argument: the test will
 * find all supported keys and sign/verify both JWT and JWS objects with all
 * keys.
 */
public class KeyRingIntegrationTest {

    /**
     * @param args
     *            First argument must be a key ring resource ID
     * @throws Exception
     *             On any errors
     */
    public static void main(String[] args) throws Exception {
        KeyRingName ring = KeyRingName.parse(args[0]);
        KeyIdGenerator gen = new Sha256KeyIdGenerator();
        Predicate<CryptoKeyVersion> filter = (k) -> true;
        try (KeyManagementServiceClient client = KeyManagementServiceClient.create()) {
            KmsKeyHandleFactory provider = KmsKeyHandleFactory.builder(client, ring)
                    .withKeyCacheDuration(Duration.ofSeconds(60)).withKeyRingFilter(filter).withKeyIdGenerator(gen)
                    .build();

            // test signing with all
            for (KmsKeyHandle h : provider.list().collect(Collectors.toList())) {
                if (h.getAlgorithm() == JWSAlgorithm.ES256K) {
                    continue;
                }
                testSignedJWT(h);
                testSignedJWS(h);
            }

            // test listing by algorithm
            System.out.println(
                    "Found " + provider.listByAlgorithm(a -> JWSAlgorithm.ES256.equals(a)).count() + " ES256 keys");
            System.out.println(
                    "Found " + provider.listByAlgorithm(a -> JWSAlgorithm.RS256.equals(a)).count() + " RS256 keys");
        }
    }

    private static void testSignedJWS(KmsKeyHandle h) throws Exception {
        // sig
        JWSObject jwsObject = new JWSObject(h.createHeaderBuilder().build(), new Payload("Hello World"));
        // sign
        jwsObject.sign(h.getSigner());
        // parse
        String token = jwsObject.serialize();
        System.out.println("JWS - " + h.getKeyId() + " / " + h.getAlgorithm() + " : " + token);
        System.out.println("JWK - " + h.getPublicKey().map(k -> k.toJSONString()).orElse("n/a"));
        jwsObject = JWSObject.parse(token);
        // check
        if (!jwsObject.verify(h.getVerifier())) {
            throw new IllegalStateException("Failed to verify JWS signature using key " + h.getKeyId());
        }
    }

    private static void testSignedJWT(KmsKeyHandle h) throws Exception {
        // claims
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("bob").issuer("https://www.google.com")
                .expirationTime(new Date(LocalDateTime.now().plusHours(24).toInstant(ZoneOffset.UTC).toEpochMilli()))
                .build();
        // jwt
        SignedJWT signedJWT = new SignedJWT(h.createHeaderBuilder().build(), claimsSet);
        signedJWT.sign(h.getSigner());
        // parse
        String token = signedJWT.serialize();
        System.out.println("JWT - " + h.getKeyId() + " / " + h.getAlgorithm() + " : " + token);
        System.out.println("JWK - " + h.getPublicKey().map(k -> k.toJSONString()).orElse("n/a"));
        signedJWT = SignedJWT.parse(token);
        // check
        if (!signedJWT.verify(h.getVerifier())) {
            throw new IllegalStateException("Failed to verify JWT signature using key " + h.getKeyId());
        }
    }
}
