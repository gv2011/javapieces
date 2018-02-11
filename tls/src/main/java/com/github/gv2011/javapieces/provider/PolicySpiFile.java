/*
 * Copyright (c) 2005, Oracle and/or its affiliates. All rights reserved.
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

import java.security.CodeSource;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Policy;
import java.security.PolicySpi;
import java.security.ProtectionDomain;
import java.security.URIParameter;

import java.net.MalformedURLException;

/**
 * This class wraps the PolicyFile subclass implementation of Policy
 * inside a PolicySpi implementation that is available from the SUN provider
 * via the Policy.getInstance calls.
 *
 */
public final class PolicySpiFile extends PolicySpi {

    private PolicyFile pf;

    public PolicySpiFile(final Policy.Parameters params) {

        if (params == null) {
            pf = new PolicyFile();
        } else {
            if (!(params instanceof URIParameter)) {
                throw new IllegalArgumentException
                        ("Unrecognized policy parameter: " + params);
            }
            final URIParameter uriParam = (URIParameter)params;
            try {
                pf = new PolicyFile(uriParam.getURI().toURL());
            } catch (final MalformedURLException mue) {
                throw new IllegalArgumentException("Invalid URIParameter", mue);
            }
        }
    }

    @Override
    protected PermissionCollection engineGetPermissions(final CodeSource codesource) {
        return pf.getPermissions(codesource);
    }

    @Override
    protected PermissionCollection engineGetPermissions(final ProtectionDomain d) {
        return pf.getPermissions(d);
    }

    @Override
    protected boolean engineImplies(final ProtectionDomain d, final Permission p) {
        return pf.implies(d, p);
    }

    @Override
    protected void engineRefresh() {
        pf.refresh();
    }
}
