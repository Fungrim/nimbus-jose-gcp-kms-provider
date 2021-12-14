package io.github.fungrim.nimbus.gcp.kms;

import java.time.Duration;
import java.util.Collections;

import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.cloud.kms.v1.Digest;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyRingName;
import com.google.protobuf.ByteString;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.BaseJWSProvider;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;

import io.github.fungrim.nimbus.gcp.KeyDiscriminator;
import io.github.fungrim.nimbus.gcp.KeyIdGenerator;

public class CryptoKeySigner extends BaseJWSProvider implements JWSSigner {

    public static void main(String[] args) throws Exception {
        KeyRingName ring = KeyRingName.parse("projects/larsan-net/locations/europe/keyRings/testrings");
        KeyIdGenerator gen = new Sha256KeyIdGenerator();
        KeyDiscriminator disc = (k) -> true;
        try (KeyManagementServiceClient client = KeyManagementServiceClient.create()) {
            SigningKeyRingAccessor acc = new SigningKeyRingAccessor(ring, client, gen, disc, Duration.ofSeconds(60));    
            // CryptoKeyVersionName keyName = CryptoKeyVersionName.parse("projects/larsan-net/locations/europe/keyRings/testrings/cryptoKeys/test-ec-sign/cryptoKeyVersions/1");
            CryptoKeyVersionName keyName = acc.fetchLatest(JWSAlgorithm.ES256).orElseThrow();
            JWK jwk = acc.getPublicKeyJwk(keyName);
            System.out.println(jwk.toJSONString());
            System.out.println("");

            CryptoKeyVersion key = acc.get(keyName);
            JWSAlgorithm alg = JwsConversions.getSigningAlgorithm(key);
            CryptoKeySigner signer = new CryptoKeySigner(key, client);
            JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(alg).keyID(jwk.getKeyID()).build(),
                new Payload("Hello World"));

            jwsObject.sign(signer);
            String s = jwsObject.serialize();
            System.out.println(s);
            System.out.println("");

            CryptoKeyVerifier verifier = new CryptoKeyVerifier(key, client);
            System.out.println("" + jwsObject.verify(verifier));
        }
    }
    
    private final KeyManagementServiceClient client;
    private final CryptoKeyVersion key;

    public CryptoKeySigner(CryptoKeyVersion key, KeyManagementServiceClient client) throws JOSEException {
        super(Collections.singleton(JwsConversions.getSigningAlgorithm(key)));
        this.client = client;
        this.key = key;
    }

    @Override
    public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
        JWSAlgorithm alg = header.getAlgorithm();
		if (!supportedJWSAlgorithms().contains(alg)) {
			throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, supportedJWSAlgorithms()));
		}
        CryptoKeyVersionName keyName = CryptoKeyVersionName.parse(key.getName());
        if(alg.getName().startsWith("HS")) {
            return Base64URL.encode(client.macSign(keyName, ByteString.copyFrom(signingInput)).toByteArray());
        } else {
            byte[] digestBytes = JwsConversions.digest(signingInput, alg);
            Digest digest = Digest.newBuilder().setSha256(ByteString.copyFrom(digestBytes)).build();
            byte[] ciphertext = client.asymmetricSign(keyName, digest).getSignature().toByteArray();
            if(JWSAlgorithm.Family.EC.contains(alg)) {
                int sigLength = ECDSA.getSignatureByteArrayLength(header.getAlgorithm());
                byte[] jwsSignature = ECDSA.transcodeSignatureToConcat(ciphertext, sigLength);
                return Base64URL.encode(jwsSignature);
            } else {
                return Base64URL.encode(ciphertext);
            }
        }
    }
}
