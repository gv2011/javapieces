/*
 * Copyright (c) 2012, Oracle and/or its affiliates. All rights reserved.
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

package com.github.gv2011.javapieces.provider;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.CertPathValidatorException;
import java.security.cert.PKIXCertPathChecker;
import java.util.Set;

import com.github.gv2011.javapieces.secutil.Debug;
import com.github.gv2011.javapieces.secutil.UntrustedCertificates;

import java.util.Collection;


/**
 * A <code>PKIXCertPathChecker</code> implementation to check whether a
 * specified certificate is distrusted.
 *
 * @see PKIXCertPathChecker
 * @see PKIXParameters
 */
final public class UntrustedChecker extends PKIXCertPathChecker {

    private static final Debug debug = Debug.getInstance("certpath");

    /**
     * Default Constructor
     */
    public UntrustedChecker() {
        // blank
    }

    @Override
    public void init(final boolean forward) throws CertPathValidatorException {
        // Note that this class supports both forward and reverse modes.
    }

    @Override
    public boolean isForwardCheckingSupported() {
        // Note that this class supports both forward and reverse modes.
        return true;
    }

    @Override
    public Set<String> getSupportedExtensions() {
        return null;
    }

    @Override
    public void check(final Certificate cert,
            final Collection<String> unresolvedCritExts)
            throws CertPathValidatorException {

        final X509Certificate currCert = (X509Certificate)cert;

        if (UntrustedCertificates.isUntrusted(currCert)) {
            if (debug != null) {
                debug.println("UntrustedChecker: untrusted certificate " +
                        currCert.getSubjectX500Principal());
            }

            throw new CertPathValidatorException(
                "Untrusted certificate: " + currCert.getSubjectX500Principal());
        }
    }
}

