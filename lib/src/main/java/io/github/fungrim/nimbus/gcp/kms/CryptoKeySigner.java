package io.github.fungrim.nimbus.gcp.kms;

import java.util.Collections;

import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.cloud.kms.v1.Digest;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.protobuf.ByteString;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.BaseJWSProvider;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.util.Base64URL;

public class CryptoKeySigner extends BaseJWSProvider implements JWSSigner {
    
    private final KeyManagementServiceClient client;
    private final CryptoKeyVersion key;

    public CryptoKeySigner(CryptoKeyVersion key, KeyManagementServiceClient client) throws JOSEException {
        super(Collections.singleton(Algorithms.getSigningAlgorithm(key)));
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
            byte[] byteArray = client.macSign(keyName, ByteString.copyFrom(signingInput)).getMac().toByteArray();
            return Base64URL.encode(byteArray);
        } else {
            byte[] digestBytes = Algorithms.digest(signingInput, alg);
            Digest digest = createDigest(digestBytes, alg);
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

    private Digest createDigest(byte[] digestBytes, JWSAlgorithm alg) {
        if(alg.getName().endsWith("256") || alg.getName().endsWith("256K")) {
            return Digest.newBuilder().setSha256(ByteString.copyFrom(digestBytes)).build();
        } else if(alg.getName().endsWith("384")) {
            return Digest.newBuilder().setSha384(ByteString.copyFrom(digestBytes)).build();
        } else {
            return Digest.newBuilder().setSha512(ByteString.copyFrom(digestBytes)).build();
        }
    }
}
