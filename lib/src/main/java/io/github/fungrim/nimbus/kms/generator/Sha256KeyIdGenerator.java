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
package io.github.fungrim.nimbus.kms.generator;


import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.common.base.Preconditions;
import com.google.common.hash.Hashing;
import io.github.fungrim.nimbus.KeyIdGenerator;
import java.nio.charset.StandardCharsets;

public class Sha256KeyIdGenerator implements KeyIdGenerator {

    @Override
    public String getKeyId(CryptoKeyVersionName key) {
        Preconditions.checkNotNull(key);
        return Hashing.sha256().hashString(key.toString(), StandardCharsets.UTF_8).toString();
    }
}
