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
package io.github.fungrim.nimbus;


import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.common.base.Preconditions;

/**
 * The ID generator is used to create stable, but obfuscated, JWK key ID:s. The
 * default implementation return a SHA-256 of the KMS resource name.
 */
@FunctionalInterface
public interface KeyIdGenerator {

    public default String getKeyId(CryptoKeyVersion key) {
        Preconditions.checkNotNull(key);
        return getKeyId(CryptoKeyVersionName.parse(key.getName()));
    }

    public String getKeyId(CryptoKeyVersionName key);

}
