/*
 * Copyright (c) 1999, 2007, Oracle and/or its affiliates. All rights reserved.
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

package com.github.gv2011.javapieces.pkcs;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;

import com.github.gv2011.javapieces.secutil.DerInputStream;
import com.github.gv2011.javapieces.secutil.DerOutputStream;
import com.github.gv2011.javapieces.secutil.DerValue;
import com.github.gv2011.javapieces.x509.AlgorithmId;




/**
 * A MacData type, as defined in PKCS#12.
 *
 * @author Sharon Liu
 */

class MacData {

    private final String digestAlgorithmName;
    @SuppressWarnings("unused")
    private final AlgorithmParameters digestAlgorithmParams;
    private byte[] digest;
    private final byte[] macSalt;
    private int iterations;

    // the ASN.1 encoded contents of this class
    private byte[] encoded = null;

    /**
     * Parses a PKCS#12 MAC data.
     */
    MacData(final DerInputStream derin)
        throws IOException, ParsingException
    {
        final DerValue[] macData = derin.getSequence(2);

        // Parse the digest info
        final DerInputStream digestIn = new DerInputStream(macData[0].toByteArray());
        final DerValue[] digestInfo = digestIn.getSequence(2);

        // Parse the DigestAlgorithmIdentifier.
        final AlgorithmId digestAlgorithmId = AlgorithmId.parse(digestInfo[0]);
        digestAlgorithmName = digestAlgorithmId.getName();
        digestAlgorithmParams = digestAlgorithmId.getParameters();
        // Get the digest.
        digest = digestInfo[1].getOctetString();

        // Get the salt.
        macSalt = macData[1].getOctetString();

        // Iterations is optional. The default value is 1.
        if (macData.length > 2) {
            iterations = macData[2].getInteger();
        } else {
            iterations = 1;
        }
    }

    MacData(final String algName, final byte[] digest, final byte[] salt, final int iterations)
        throws NoSuchAlgorithmException
    {
        if (algName == null)
           throw new NullPointerException("the algName parameter " +
                                               "must be non-null");

        final AlgorithmId algid = AlgorithmId.get(algName);
        digestAlgorithmName = algid.getName();
        digestAlgorithmParams = algid.getParameters();

        if (digest == null) {
            throw new NullPointerException("the digest " +
                                           "parameter must be non-null");
        } else if (digest.length == 0) {
            throw new IllegalArgumentException("the digest " +
                                                "parameter must not be empty");
        } else {
            this.digest = digest.clone();
        }

        macSalt = salt;
        this.iterations = iterations;

        // delay the generation of ASN.1 encoding until
        // getEncoded() is called
        encoded = null;

    }

    MacData(final AlgorithmParameters algParams, final byte[] digest,
        final byte[] salt, final int iterations) throws NoSuchAlgorithmException
    {
        if (algParams == null)
           throw new NullPointerException("the algParams parameter " +
                                               "must be non-null");

        final AlgorithmId algid = AlgorithmId.get(algParams);
        digestAlgorithmName = algid.getName();
        digestAlgorithmParams = algid.getParameters();

        if (digest == null) {
            throw new NullPointerException("the digest " +
                                           "parameter must be non-null");
        } else if (digest.length == 0) {
            throw new IllegalArgumentException("the digest " +
                                                "parameter must not be empty");
        } else {
            this.digest = digest.clone();
        }

        macSalt = salt;
        this.iterations = iterations;

        // delay the generation of ASN.1 encoding until
        // getEncoded() is called
        encoded = null;

    }

    String getDigestAlgName() {
        return digestAlgorithmName;
    }

    byte[] getSalt() {
        return macSalt;
    }

    int getIterations() {
        return iterations;
    }

    byte[] getDigest() {
        return digest;
    }

    /**
     * Returns the ASN.1 encoding of this object.
     * @return the ASN.1 encoding.
     * @exception IOException if error occurs when constructing its
     * ASN.1 encoding.
     */
    public byte[] getEncoded() throws NoSuchAlgorithmException, IOException
    {
        if (encoded != null)
            return encoded.clone();

        @SuppressWarnings("resource")
        final DerOutputStream out = new DerOutputStream();
        final DerOutputStream tmp = new DerOutputStream();

        final DerOutputStream tmp2 = new DerOutputStream();
        // encode encryption algorithm
        final AlgorithmId algid = AlgorithmId.get(digestAlgorithmName);
        algid.encode(tmp2);

        // encode digest data
        tmp2.putOctetString(digest);

        tmp.write(DerValue.tag_Sequence, tmp2);

        // encode salt
        tmp.putOctetString(macSalt);

        // encode iterations
        tmp.putInteger(iterations);

        // wrap everything into a SEQUENCE
        out.write(DerValue.tag_Sequence, tmp);
        encoded = out.toByteArray();

        return encoded.clone();
    }

}
