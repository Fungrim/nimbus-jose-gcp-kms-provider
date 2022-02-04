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
package io.github.fungrim.nimbus.kms.client;


import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.nimbusds.jose.JWSAlgorithm;
import java.util.function.Predicate;
import java.util.stream.Stream;

public interface KmsServiceClient {

    public boolean macVerify(CryptoKeyVersionName keyName, byte[] signingInput, byte[] signature);

    public byte[] getPublicKeyPem(CryptoKeyVersionName keyName);

    public CryptoKeyVersion getKey(CryptoKeyVersionName keyName);

    public Stream<CryptoKeyVersion> list(Predicate<CryptoKeyVersion> filter);

    public byte[] macSign(CryptoKeyVersionName keyName, byte[] signingInput);

    public byte[] asymmetricSign(CryptoKeyVersionName keyName, JWSAlgorithm algorithm, byte[] digestBytes);

}
