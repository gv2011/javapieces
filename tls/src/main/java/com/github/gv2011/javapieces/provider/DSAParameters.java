/*
 * Copyright (c) 1997, 2011, Oracle and/or its affiliates. All rights reserved.
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

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import com.github.gv2011.javapieces.secutil.Debug;
import com.github.gv2011.javapieces.secutil.DerOutputStream;
import com.github.gv2011.javapieces.secutil.DerValue;



/**
 * This class implements the parameter set used by the
 * Digital Signature Algorithm as specified in the FIPS 186
 * standard.
 *
 * @author Jan Luehe
 *
 *
 * @since 1.2
 */

public class DSAParameters extends AlgorithmParametersSpi {

    // the prime (p)
    protected BigInteger p;

    // the sub-prime (q)
    protected BigInteger q;

    // the base (g)
    protected BigInteger g;

    @Override
    protected void engineInit(final AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException {
            if (!(paramSpec instanceof DSAParameterSpec)) {
                throw new InvalidParameterSpecException
                    ("Inappropriate parameter specification");
            }
            p = ((DSAParameterSpec)paramSpec).getP();
            q = ((DSAParameterSpec)paramSpec).getQ();
            g = ((DSAParameterSpec)paramSpec).getG();
    }

    @Override
    protected void engineInit(final byte[] params) throws IOException {
        final DerValue encodedParams = new DerValue(params);

        if (encodedParams.tag != DerValue.tag_Sequence) {
            throw new IOException("DSA params parsing error");
        }

        encodedParams.data.reset();

        p = encodedParams.data.getBigInteger();
        q = encodedParams.data.getBigInteger();
        g = encodedParams.data.getBigInteger();

        if (encodedParams.data.available() != 0) {
            throw new IOException("encoded params have " +
                                  encodedParams.data.available() +
                                  " extra bytes");
        }
    }

    @Override
    protected void engineInit(final byte[] params, final String decodingMethod)
        throws IOException {
            engineInit(params);
    }

    @Override
    protected <T extends AlgorithmParameterSpec>
        T engineGetParameterSpec(final Class<T> paramSpec)
        throws InvalidParameterSpecException
    {
            try {
                final Class<?> dsaParamSpec = Class.forName
                    ("java.security.spec.DSAParameterSpec");
                if (dsaParamSpec.isAssignableFrom(paramSpec)) {
                    return paramSpec.cast(
                            new DSAParameterSpec(p, q, g));
                } else {
                    throw new InvalidParameterSpecException
                        ("Inappropriate parameter Specification");
                }
            } catch (final ClassNotFoundException e) {
                throw new InvalidParameterSpecException
                    ("Unsupported parameter specification: " + e.getMessage());
            }
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        @SuppressWarnings("resource")
        final DerOutputStream out = new DerOutputStream();
        final DerOutputStream bytes = new DerOutputStream();

        bytes.putInteger(p);
        bytes.putInteger(q);
        bytes.putInteger(g);
        out.write(DerValue.tag_Sequence, bytes);
        return out.toByteArray();
    }

    @Override
    protected byte[] engineGetEncoded(final String encodingMethod)
        throws IOException {
            return engineGetEncoded();
    }

    /*
     * Returns a formatted string describing the parameters.
     */
    @Override
    protected String engineToString() {
        return "\n\tp: " + Debug.toHexString(p)
            + "\n\tq: " + Debug.toHexString(q)
            + "\n\tg: " + Debug.toHexString(g)
            + "\n";
    }
}
