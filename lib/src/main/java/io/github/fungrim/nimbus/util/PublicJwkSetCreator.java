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
package io.github.fungrim.nimbus.util;


import com.google.common.base.Preconditions;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import io.github.fungrim.nimbus.KmsKeyHandle;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * This is a utility class to create a JWK set from {@link KmsKeyHandle}
 * objects. It will only return public keys, and will filter out HMAC keys for
 * the same reason.
 */
public class PublicJwkSetCreator {

    private PublicJwkSetCreator() {
    }

    /**
     * @param stream
     *            Stream to read keys from, must not be null
     * @return A new JWK set, never null
     * @throws JOSEException
     *             On Jose errors
     */
    public static JWKSet of(Stream<KmsKeyHandle> stream) throws JOSEException {
        Preconditions.checkNotNull(stream);
        return of(stream.collect(Collectors.toList()));
    }

    /**
     * @param list
     *            List to read keys from, must not be null
     * @return A new JWK set, never null
     * @throws JOSEException
     *             On Jose errors
     */
    public static JWKSet of(List<KmsKeyHandle> list) throws JOSEException {
        Preconditions.checkNotNull(list);
        List<JWK> jwks = new ArrayList<>(list.size());
        for (KmsKeyHandle h : list) {
            Optional<JWK> key = h.getPublicKey();
            if (key.isPresent()) {
                jwks.add(key.get());
            }
        }
        return new JWKSet(jwks);
    }

    /**
     * @param handles
     *            Handle array to read keys from, must not be null
     * @return A new JWK set, never null
     * @throws JOSEException
     *             On Jose errors
     */
    public static JWKSet of(KmsKeyHandle... handles) throws JOSEException {
        Preconditions.checkNotNull(handles);
        return of(Arrays.asList(handles));
    }
}
