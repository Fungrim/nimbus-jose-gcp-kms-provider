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
package io.github.fungrim.nimbus.jose;


import com.nimbusds.jose.JOSEException;

/**
 * This exception is used for when the code point has already passed places
 * where checked JOSE exceptions has already been thrown. As such, it is an
 * illegal state and represents a bug or an outdated library.
 */
public class UncheckedJoseException extends IllegalStateException {

    public UncheckedJoseException(JOSEException e) {
        super(e);
    }
}
