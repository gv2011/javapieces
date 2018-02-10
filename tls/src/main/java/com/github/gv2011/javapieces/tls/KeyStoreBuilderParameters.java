/*
 * Copyright (c) 2003, 2011, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package com.github.gv2011.javapieces.tls;

/*-
 * #%L
 * javapieces-tls
 * %%
 * Copyright (C) 2018 Vinz (https://github.com/gv2011)
 * %%
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * #L%
 */
import java.security.KeyStore.Builder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * A parameters object for X509KeyManagers that encapsulates a List
 * of KeyStore.Builders.
 *
 * @see java.security.KeyStore.Builder
 * @see X509KeyManager
 *
 * @author  Andreas Sterbenz
 * @since   1.5
 */
public class KeyStoreBuilderParameters implements ManagerFactoryParameters {

    private final List<Builder> parameters;

    /**
     * Construct new KeyStoreBuilderParameters from the specified
     * {@linkplain java.security.KeyStore.Builder}.
     *
     * @param builder the Builder object
     * @exception NullPointerException if builder is null
     */
    public KeyStoreBuilderParameters(final Builder builder) {
        parameters = Collections.singletonList(Objects.requireNonNull(builder));
    }

    /**
     * Construct new KeyStoreBuilderParameters from a List
     * of {@linkplain java.security.KeyStore.Builder}s. Note that the list
     * is cloned to protect against subsequent modification.
     *
     * @param parameters the List of Builder objects
     * @exception NullPointerException if parameters is null
     * @exception IllegalArgumentException if parameters is an empty list
     */
    public KeyStoreBuilderParameters(final List<Builder> parameters) {
        if (parameters.isEmpty()) {
            throw new IllegalArgumentException();
        }

        this.parameters = Collections.unmodifiableList(
            new ArrayList<>(parameters));
    }

    /**
     * Return the unmodifiable List of the
     * {@linkplain java.security.KeyStore.Builder}s
     * encapsulated by this object.
     *
     * @return the unmodifiable List of the
     * {@linkplain java.security.KeyStore.Builder}s
     * encapsulated by this object.
     */
    public List<Builder> getParameters() {
        return parameters;
    }

}
