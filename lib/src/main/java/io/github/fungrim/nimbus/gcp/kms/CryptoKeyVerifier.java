package io.github.fungrim.nimbus.gcp.kms;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Collections;

import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.MacVerifyResponse;
import com.google.protobuf.ByteString;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.BaseJWSProvider;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.util.Base64URL;

public class CryptoKeyVerifier extends BaseJWSProvider implements JWSVerifier {

    private final KeyManagementServiceClient client;
    private final CryptoKeyVersion key;
    private final PublicKey publicKey;

    public CryptoKeyVerifier(CryptoKeyVersion key, KeyManagementServiceClient client) throws JOSEException {
        super(Collections.singleton(JwsConversions.getSigningAlgorithm(key)));
        this.client = client;
        this.key = key;
        this.publicKey = toPublicKey();
    }

    @Override
    public boolean verify(JWSHeader header, byte[] signingInput, Base64URL signature) throws JOSEException {
        JWSAlgorithm alg = header.getAlgorithm();
		if (!supportedJWSAlgorithms().contains(alg)) {
			throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, supportedJWSAlgorithms()));
		}
        if(alg.getName().startsWith("HS")) {
            CryptoKeyVersionName keyName = CryptoKeyVersionName.parse(key.getName());
            MacVerifyResponse response = client.macVerify(keyName, ByteString.copyFrom(signingInput), ByteString.copyFrom(signature.decode()));
            return response.getSuccess();
        } else {
            try {
                byte[] signatureBytes = signature.decode();
                Signature sig = Signature.getInstance(JcaConversions.getSignatureAlgorithmName(key));
                sig.initVerify(this.publicKey);
                sig.update(signingInput);
                if(JWSAlgorithm.Family.EC.contains(alg)) { 
                    if (ECDSA.getSignatureByteArrayLength(header.getAlgorithm()) != signatureBytes.length) {
                        return false; // from Nimbus
                    }
                    byte[] derSignature = ECDSA.transcodeSignatureToDER(signatureBytes);
                    return sig.verify(derSignature);
                } else {
                    return sig.verify(signatureBytes);
                }
            } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                throw new JOSEException("Failed to create JCA signature", e);
            }
        }
    }

    private PublicKey toPublicKey() throws JOSEException {
        com.google.cloud.kms.v1.PublicKey publicKey = client.getPublicKey(CryptoKeyVersionName.parse(key.getName()));
        byte[] pem = publicKey.getPemBytes().toByteArray();
        return JwsConversions.toPublicKey(key, pem);
    }
}
