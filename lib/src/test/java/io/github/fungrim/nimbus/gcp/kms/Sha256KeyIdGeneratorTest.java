package io.github.fungrim.nimbus.gcp.kms;

import com.google.cloud.kms.v1.CryptoKeyVersionName;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class Sha256KeyIdGeneratorTest {

    @Test
    public void testGeneration() {
        CryptoKeyVersionName key = CryptoKeyVersionName.of("project", "location", "key-ring", "key", "version");
        Assertions.assertEquals("bf378480728786fd6a52cf552342f0ce6012413f6fd5d03c67af8b4132355858", new Sha256KeyIdGenerator().getKeyId(key));
    }
}
