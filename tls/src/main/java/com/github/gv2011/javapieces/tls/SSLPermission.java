/*
 * Copyright (c) 2000, 2017, Oracle and/or its affiliates. All rights reserved.
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
import java.security.BasicPermission;

/**
 * This class is for various network permissions.
 * An SSLPermission contains a name (also referred to as a "target name") but
 * no actions list; you either have the named permission
 * or you don't.
 * <P>
 * The target name is the name of the network permission (see below). The naming
 * convention follows the  hierarchical property naming convention.
 * Also, an asterisk
 * may appear at the end of the name, following a ".", or by itself, to
 * signify a wildcard match. For example: "foo.*" and "*" signify a wildcard
 * match, while "*foo" and "a*b" do not.
 * <P>
 * The following table lists all the possible SSLPermission target names,
 * and for each provides a description of what the permission allows
 * and a discussion of the risks of granting code the permission.
 *
 * <table class="striped">
 * <caption style="display:none">permission name, what it allows, and associated risks</caption>
 * <thead>
 * <tr>
 * <th>Permission Target Name</th>
 * <th>What the Permission Allows</th>
 * <th>Risks of Allowing this Permission</th>
 * </tr>
 * </thead>
 *
 * <tbody>
 * <tr>
 *   <td>setHostnameVerifier</td>
 *   <td>The ability to set a callback which can decide whether to
 * allow a mismatch between the host being connected to by
 * an HttpsURLConnection and the common name field in
 * server certificate.
 *  </td>
 *   <td>Malicious
 * code can set a verifier that monitors host names visited by
 * HttpsURLConnection requests or that allows server certificates
 * with invalid common names.
 * </td>
 * </tr>
 *
 * <tr>
 *   <td>getSSLSessionContext</td>
 *   <td>The ability to get the SSLSessionContext of an SSLSession.
 * </td>
 *   <td>Malicious code may monitor sessions which have been established
 * with SSL peers or might invalidate sessions to slow down performance.
 * </td>
 * </tr>
 *
 * <tr>
 *   <td>setDefaultSSLContext</td>
 *   <td>The ability to set the default SSL context
 * </td>
 *   <td>Malicious code can set a context that monitors the opening of
 * connections or the plaintext data that is transmitted.
 * </td>
 * </tr>
 *
 * </tbody>
 * </table>
 *
 * @see java.security.BasicPermission
 * @see java.security.Permission
 * @see java.security.Permissions
 * @see java.security.PermissionCollection
 * @see java.lang.SecurityManager
 *
 * @since 1.4
 * @author Marianne Mueller
 * @author Roland Schemers
 */

public final class SSLPermission extends BasicPermission {

    private static final long serialVersionUID = -3456898025505876775L;

    /**
     * Creates a new SSLPermission with the specified name.
     * The name is the symbolic name of the SSLPermission, such as
     * "setDefaultAuthenticator", etc. An asterisk
     * may appear at the end of the name, following a ".", or by itself, to
     * signify a wildcard match.
     *
     * @param name the name of the SSLPermission.
     *
     * @throws NullPointerException if <code>name</code> is null.
     * @throws IllegalArgumentException if <code>name</code> is empty.
     */

    public SSLPermission(final String name)
    {
        super(name);
    }

    /**
     * Creates a new SSLPermission object with the specified name.
     * The name is the symbolic name of the SSLPermission, and the
     * actions String is currently unused and should be null.
     *
     * @param name the name of the SSLPermission.
     * @param actions ignored.
     *
     * @throws NullPointerException if <code>name</code> is null.
     * @throws IllegalArgumentException if <code>name</code> is empty.
     */

    public SSLPermission(final String name, final String actions)
    {
        super(name, actions);
    }
}
