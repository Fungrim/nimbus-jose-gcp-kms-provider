package io.github.fungrim.nimbus.kms.generator;

import java.nio.charset.StandardCharsets;

import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.common.base.Preconditions;
import com.google.common.hash.Hashing;

import io.github.fungrim.nimbus.KeyIdGenerator;

public class Sha256KeyIdGenerator implements KeyIdGenerator {
    
    @Override
    public String getKeyId(CryptoKeyVersionName key) {
        Preconditions.checkNotNull(key);
        return Hashing.sha256().hashString(key.toString(), StandardCharsets.UTF_8).toString();
    }
}
