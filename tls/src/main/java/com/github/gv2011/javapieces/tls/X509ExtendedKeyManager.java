/*
 * Copyright (c) 2004, Oracle and/or its affiliates. All rights reserved.
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
import java.security.Principal;



/**
 * Abstract class that provides for extension of the X509KeyManager
 * interface.
 * <P>
 * Methods in this class should be overriden to provide actual
 * implementations.
 *
 * @since 1.5
 * @author Brad R. Wetmore
 */
public abstract class X509ExtendedKeyManager implements X509KeyManager {

    /**
     * Constructor used by subclasses only.
     */
    protected X509ExtendedKeyManager() {
    }

    /**
     * Choose an alias to authenticate the client side of an
     * <code>SSLEngine</code> connection given the public key type
     * and the list of certificate issuer authorities recognized by
     * the peer (if any).
     * <P>
     * The default implementation returns null.
     *
     * @param keyType the key algorithm type name(s), ordered
     *          with the most-preferred key type first.
     * @param issuers the list of acceptable CA issuer subject names
     *          or null if it does not matter which issuers are used.
     * @param engine the <code>SSLEngine</code> to be used for this
     *          connection.  This parameter can be null, which indicates
     *          that implementations of this interface are free to
     *          select an alias applicable to any engine.
     * @return the alias name for the desired key, or null if there
     *          are no matches.
     */
    public String chooseEngineClientAlias(final String[] keyType,
            final Principal[] issuers, final SSLEngine engine) {
        return null;
    }

    /**
     * Choose an alias to authenticate the server side of an
     * <code>SSLEngine</code> connection given the public key type
     * and the list of certificate issuer authorities recognized by
     * the peer (if any).
     * <P>
     * The default implementation returns null.
     *
     * @param keyType the key algorithm type name.
     * @param issuers the list of acceptable CA issuer subject names
     *          or null if it does not matter which issuers are used.
     * @param engine the <code>SSLEngine</code> to be used for this
     *          connection.  This parameter can be null, which indicates
     *          that implementations of this interface are free to
     *          select an alias applicable to any engine.
     * @return the alias name for the desired key, or null if there
     *          are no matches.
     */
    public String chooseEngineServerAlias(final String keyType,
            final Principal[] issuers, final SSLEngine engine) {
        return null;
    }

}
