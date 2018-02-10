/*
 * Copyright (c) 1999, 2015, Oracle and/or its affiliates. All rights reserved.
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
 * for the {@code SSLContext} class.
 *
 * <p> All the abstract methods in this class must be implemented by each
 * cryptographic service provider who wishes to supply the implementation
 * of a particular SSL context.
 *
 * @since 1.4
 * @see SSLContext
 */
public abstract class SSLContextSpi {
    /**
     * Initializes this context.
     *
     * @param km the sources of authentication keys
     * @param tm the sources of peer authentication trust decisions
     * @param sr the source of randomness
     * @throws KeyManagementException if this operation fails
     * @see SSLContext#init(KeyManager [], TrustManager [], SecureRandom)
     */
    protected abstract void engineInit(KeyManager[] km, TrustManager[] tm,
        SecureRandom sr) throws KeyManagementException;

    /**
     * Returns a {@code SocketFactory} object for this
     * context.
     *
     * @return the {@code SocketFactory} object
     * @throws UnsupportedOperationException if the underlying provider
     *         does not implement the operation.
     * @throws IllegalStateException if the SSLContextImpl requires
     *         initialization and the {@code engineInit()}
     *         has not been called
     * @see com.github.gv2011.javapieces.tls.SSLContext#getSocketFactory()
     */
    protected abstract SSLSocketFactory engineGetSocketFactory();

    /**
     * Returns a {@code ServerSocketFactory} object for
     * this context.
     *
     * @return the {@code ServerSocketFactory} object
     * @throws UnsupportedOperationException if the underlying provider
     *         does not implement the operation.
     * @throws IllegalStateException if the SSLContextImpl requires
     *         initialization and the {@code engineInit()}
     *         has not been called
     * @see com.github.gv2011.javapieces.tls.SSLContext#getServerSocketFactory()
     */
    protected abstract SSLServerSocketFactory engineGetServerSocketFactory();

    /**
     * Creates a new {@code SSLEngine} using this context.
     * <P>
     * Applications using this factory method are providing no hints
     * for an internal session reuse strategy. If hints are desired,
     * {@link #engineCreateSSLEngine(String, int)} should be used
     * instead.
     * <P>
     * Some cipher suites (such as Kerberos) require remote hostname
     * information, in which case this factory method should not be used.
     *
     * @return  the {@code SSLEngine} Object
     * @throws IllegalStateException if the SSLContextImpl requires
     *         initialization and the {@code engineInit()}
     *         has not been called
     *
     * @see     SSLContext#createSSLEngine()
     *
     * @since   1.5
     */
    protected abstract SSLEngine engineCreateSSLEngine();

    /**
     * Creates a {@code SSLEngine} using this context.
     * <P>
     * Applications using this factory method are providing hints
     * for an internal session reuse strategy.
     * <P>
     * Some cipher suites (such as Kerberos) require remote hostname
     * information, in which case peerHost needs to be specified.
     *
     * @param host the non-authoritative name of the host
     * @param port the non-authoritative port
     * @return  the {@code SSLEngine} Object
     * @throws IllegalStateException if the SSLContextImpl requires
     *         initialization and the {@code engineInit()}
     *         has not been called
     *
     * @see     SSLContext#createSSLEngine(String, int)
     *
     * @since   1.5
     */
    protected abstract SSLEngine engineCreateSSLEngine(String host, int port);

    /**
     * Returns a server {@code SSLSessionContext} object for
     * this context.
     *
     * @return the {@code SSLSessionContext} object
     * @see com.github.gv2011.javapieces.tls.SSLContext#getServerSessionContext()
     */
    protected abstract SSLSessionContext engineGetServerSessionContext();

    /**
     * Returns a client {@code SSLSessionContext} object for
     * this context.
     *
     * @return the {@code SSLSessionContext} object
     * @see com.github.gv2011.javapieces.tls.SSLContext#getClientSessionContext()
     */
    protected abstract SSLSessionContext engineGetClientSessionContext();

    private SSLSocket getDefaultSocket() {
        try {
            final SSLSocketFactory factory = engineGetSocketFactory();
            return (SSLSocket)factory.createSocket();
        } catch (final java.io.IOException e) {
            throw new UnsupportedOperationException("Could not obtain parameters", e);
        }
    }

    /**
     * Returns a copy of the SSLParameters indicating the default
     * settings for this SSL context.
     *
     * <p>The parameters will always have the ciphersuite and protocols
     * arrays set to non-null values.
     *
     * <p>The default implementation obtains the parameters from an
     * SSLSocket created by calling the
     * {@linkplain javax.net.SocketFactory#createSocket
     * SocketFactory.createSocket()} method of this context's SocketFactory.
     *
     * @return a copy of the SSLParameters object with the default settings
     * @throws UnsupportedOperationException if the default SSL parameters
     *   could not be obtained.
     *
     * @since 1.6
     */
    protected SSLParameters engineGetDefaultSSLParameters() {
        final SSLSocket socket = getDefaultSocket();
        return socket.getSSLParameters();
    }

    /**
     * Returns a copy of the SSLParameters indicating the maximum supported
     * settings for this SSL context.
     *
     * <p>The parameters will always have the ciphersuite and protocols
     * arrays set to non-null values.
     *
     * <p>The default implementation obtains the parameters from an
     * SSLSocket created by calling the
     * {@linkplain javax.net.SocketFactory#createSocket
     * SocketFactory.createSocket()} method of this context's SocketFactory.
     *
     * @return a copy of the SSLParameters object with the maximum supported
     *   settings
     * @throws UnsupportedOperationException if the supported SSL parameters
     *   could not be obtained.
     *
     * @since 1.6
     */
    protected SSLParameters engineGetSupportedSSLParameters() {
        final SSLSocket socket = getDefaultSocket();
        final SSLParameters params = new SSLParameters();
        params.setCipherSuites(socket.getSupportedCipherSuites());
        params.setProtocols(socket.getSupportedProtocols());
        return params;
    }

}
