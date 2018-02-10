/*
 * Copyright (c) 1999, 2001, Oracle and/or its affiliates. All rights reserved.
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
import java.security.*;



/**
 * This class defines the <i>Service Provider Interface</i> (<b>SPI</b>)
 * for the <code>KeyManagerFactory</code> class.
 *
 * <p> All the abstract methods in this class must be implemented by each
 * cryptographic service provider who wishes to supply the implementation
 * of a particular key manager factory.
 *
 * @since 1.4
 * @see KeyManagerFactory
 * @see KeyManager
 */
public abstract class KeyManagerFactorySpi {
    /**
     * Initializes this factory with a source of key material.
     *
     * @param ks the key store or null
     * @param password the password for recovering keys
     * @throws KeyStoreException if this operation fails
     * @throws NoSuchAlgorithmException if the specified algorithm is not
     *          available from the specified provider.
     * @throws UnrecoverableKeyException if the key cannot be recovered
     * @see KeyManagerFactory#init(KeyStore, char[])
     */
    protected abstract void engineInit(KeyStore ks, char[] password) throws
        KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException;

    /**
     * Initializes this factory with a source of key material.
     * <P>
     * In some cases, initialization parameters other than a keystore
     * and password may be needed by a provider.  Users of that
     * particular provider are expected to pass an implementation of
     * the appropriate <CODE>ManagerFactoryParameters</CODE> as
     * defined by the provider.  The provider can then call the
     * specified methods in the ManagerFactoryParameters
     * implementation to obtain the needed information.
     *
     * @param spec an implementation of a provider-specific parameter
     *          specification
     * @throws InvalidAlgorithmParameterException if there is problem
     *          with the parameters
     * @see KeyManagerFactory#init(ManagerFactoryParameters spec)
     */
    protected abstract void engineInit(ManagerFactoryParameters spec)
        throws InvalidAlgorithmParameterException;

    /**
     * Returns one key manager for each type of key material.
     *
     * @return the key managers
     * @throws IllegalStateException
     *         if the KeyManagerFactorySpi is not initialized
     */
    protected abstract KeyManager[] engineGetKeyManagers();
}
