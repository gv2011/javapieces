/*
 * Copyright (c) 1996, 2017, Oracle and/or its affiliates. All rights reserved.
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
import java.nio.ByteBuffer;
import java.security.DigestException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.DSAParams;
import java.util.Arrays;

import com.github.gv2011.javapieces.jca.JCAUtil;
import com.github.gv2011.javapieces.secutil.Debug;
import com.github.gv2011.javapieces.secutil.DerInputStream;
import com.github.gv2011.javapieces.secutil.DerOutputStream;
import com.github.gv2011.javapieces.secutil.DerValue;



/**
 * The Digital Signature Standard (using the Digital Signature
 * Algorithm), as described in fips186-3 of the National Instute of
 * Standards and Technology (NIST), using SHA digest algorithms
 * from FIPS180-3.
 *
 * This file contains both the signature implementation for the
 * commonly used SHA1withDSA (DSS), SHA224withDSA, SHA256withDSA,
 * as well as RawDSA, used by TLS among others. RawDSA expects
 * the 20 byte SHA-1 digest as input via update rather than the
 * original data like other signature implementations.
 *
 * @author Benjamin Renaud
 *
 * @since   1.1
 *
 * @see DSAPublicKey
 * @see DSAPrivateKey
 */
abstract class DSA extends SignatureSpi {

    /* Are we debugging? */
    private static final boolean debug = false;

    /* The number of bits used in exponent blinding */
    private static final int BLINDING_BITS = 7;

    /* The constant component of the exponent blinding value */
    private static final BigInteger BLINDING_CONSTANT =
        BigInteger.valueOf(1 << BLINDING_BITS);

    /* The parameter object */
    @SuppressWarnings("unused")
    private DSAParams params;

    /* algorithm parameters */
    private BigInteger presetP, presetQ, presetG;

    /* The public key, if any */
    private BigInteger presetY;

    /* The private key, if any */
    private BigInteger presetX;

    /* The RNG used to output a seed for generating k */
    private SecureRandom signingRandom;

    /* The message digest object used */
    private final MessageDigest md;

    /**
     * Construct a blank DSA object. It must be
     * initialized before being usable for signing or verifying.
     */
    DSA(final MessageDigest md) {
        super();
        this.md = md;
    }

    private static void checkKey(final DSAParams params, final int digestLen, final String mdAlgo)
        throws InvalidKeyException {
        // FIPS186-3 states in sec4.2 that a hash function which provides
        // a lower security strength than the (L, N) pair ordinarily should
        // not be used.
        final int valueN = params.getQ().bitLength();
        if (valueN > digestLen) {
            throw new InvalidKeyException("The security strength of " +
                mdAlgo + " digest algorithm is not sufficient for this key size");
        }
    }

    /**
     * Initialize the DSA object with a DSA private key.
     *
     * @param privateKey the DSA private key
     *
     * @exception InvalidKeyException if the key is not a valid DSA private
     * key.
     */
    @Override
    protected void engineInitSign(final PrivateKey privateKey)
            throws InvalidKeyException {
        if (!(privateKey instanceof java.security.interfaces.DSAPrivateKey)) {
            throw new InvalidKeyException("not a DSA private key: " +
                                          privateKey);
        }

        final java.security.interfaces.DSAPrivateKey priv =
            (java.security.interfaces.DSAPrivateKey)privateKey;

        // check for algorithm specific constraints before doing initialization
        final DSAParams params = priv.getParams();
        if (params == null) {
            throw new InvalidKeyException("DSA private key lacks parameters");
        }

        // check key size against hash output size for signing
        // skip this check for verification to minimize impact on existing apps
        if (md.getAlgorithm() != "NullDigest20") {
            checkKey(params, md.getDigestLength()*8, md.getAlgorithm());
        }

        this.params = params;
        presetX = priv.getX();
        presetY = null;
        presetP = params.getP();
        presetQ = params.getQ();
        presetG = params.getG();
        md.reset();
    }
    /**
     * Initialize the DSA object with a DSA public key.
     *
     * @param publicKey the DSA public key.
     *
     * @exception InvalidKeyException if the key is not a valid DSA public
     * key.
     */
    @Override
    protected void engineInitVerify(final PublicKey publicKey)
            throws InvalidKeyException {
        if (!(publicKey instanceof java.security.interfaces.DSAPublicKey)) {
            throw new InvalidKeyException("not a DSA public key: " +
                                          publicKey);
        }
        final java.security.interfaces.DSAPublicKey pub =
            (java.security.interfaces.DSAPublicKey)publicKey;

        // check for algorithm specific constraints before doing initialization
        final DSAParams params = pub.getParams();
        if (params == null) {
            throw new InvalidKeyException("DSA public key lacks parameters");
        }
        this.params = params;
        presetY = pub.getY();
        presetX = null;
        presetP = params.getP();
        presetQ = params.getQ();
        presetG = params.getG();
        md.reset();
    }

    /**
     * Update a byte to be signed or verified.
     */
    @Override
    protected void engineUpdate(final byte b) {
        md.update(b);
    }

    /**
     * Update an array of bytes to be signed or verified.
     */
    @Override
    protected void engineUpdate(final byte[] data, final int off, final int len) {
        md.update(data, off, len);
    }

    @Override
    protected void engineUpdate(final ByteBuffer b) {
        md.update(b);
    }


    /**
     * Sign all the data thus far updated. The signature is formatted
     * according to the Canonical Encoding Rules, returned as a DER
     * sequence of Integer, r and s.
     *
     * @return a signature block formatted according to the Canonical
     * Encoding Rules.
     *
     * @exception SignatureException if the signature object was not
     * properly initialized, or if another exception occurs.
     *
     * @see com.github.gv2011.javapieces.provider.DSA#engineUpdate
     * @see com.github.gv2011.javapieces.provider.DSA#engineVerify
     */
    @Override
    protected byte[] engineSign() throws SignatureException {
        final BigInteger k = generateK(presetQ);
        final BigInteger r = generateR(presetP, presetQ, presetG, k);
        final BigInteger s = generateS(presetX, presetQ, r, k);

        try {
            @SuppressWarnings("resource")
            final DerOutputStream outseq = new DerOutputStream(100);
            outseq.putInteger(r);
            outseq.putInteger(s);
            final DerValue result = new DerValue(DerValue.tag_Sequence,
                                           outseq.toByteArray());

            return result.toByteArray();

        } catch (final IOException e) {
            throw new SignatureException("error encoding signature");
        }
    }

    /**
     * Verify all the data thus far updated.
     *
     * @param signature the alledged signature, encoded using the
     * Canonical Encoding Rules, as a sequence of integers, r and s.
     *
     * @exception SignatureException if the signature object was not
     * properly initialized, or if another exception occurs.
     *
     * @see com.github.gv2011.javapieces.provider.DSA#engineUpdate
     * @see com.github.gv2011.javapieces.provider.DSA#engineSign
     */
    @Override
    protected boolean engineVerify(final byte[] signature)
            throws SignatureException {
        return engineVerify(signature, 0, signature.length);
    }

    /**
     * Verify all the data thus far updated.
     *
     * @param signature the alledged signature, encoded using the
     * Canonical Encoding Rules, as a sequence of integers, r and s.
     *
     * @param offset the offset to start from in the array of bytes.
     *
     * @param length the number of bytes to use, starting at offset.
     *
     * @exception SignatureException if the signature object was not
     * properly initialized, or if another exception occurs.
     *
     * @see com.github.gv2011.javapieces.provider.DSA#engineUpdate
     * @see com.github.gv2011.javapieces.provider.DSA#engineSign
     */
    @Override
    protected boolean engineVerify(final byte[] signature, final int offset, final int length)
            throws SignatureException {

        BigInteger r = null;
        BigInteger s = null;
        // first decode the signature.
        try {
            // Enforce strict DER checking for signatures
            final DerInputStream in =
                new DerInputStream(signature, offset, length, false);
            final DerValue[] values = in.getSequence(2);

            // check number of components in the read sequence
            // and trailing data
            if ((values.length != 2) || (in.available() != 0)) {
                throw new IOException("Invalid encoding for signature");
            }
            r = values[0].getBigInteger();
            s = values[1].getBigInteger();
        } catch (final IOException e) {
            throw new SignatureException("Invalid encoding for signature", e);
        }

        // some implementations do not correctly encode values in the ASN.1
        // 2's complement format. force r and s to be positive in order to
        // to validate those signatures
        if (r.signum() < 0) {
            r = new BigInteger(1, r.toByteArray());
        }
        if (s.signum() < 0) {
            s = new BigInteger(1, s.toByteArray());
        }

        if ((r.compareTo(presetQ) == -1) && (s.compareTo(presetQ) == -1)) {
            final BigInteger w = generateW(presetP, presetQ, presetG, s);
            final BigInteger v = generateV(presetY, presetP, presetQ, presetG, w, r);
            return v.equals(r);
        } else {
            throw new SignatureException("invalid signature: out of range values");
        }
    }

    @Override
    @Deprecated
    protected void engineSetParameter(final String key, final Object param) {
        throw new InvalidParameterException("No parameter accepted");
    }

    @Override
    @Deprecated
    protected Object engineGetParameter(final String key) {
        return null;
    }


    private BigInteger generateR(final BigInteger p, final BigInteger q, final BigInteger g,
                         BigInteger k) {

        // exponent blinding to hide information from timing channel
        final SecureRandom random = getSigningRandom();
        // start with a random blinding component
        BigInteger blindingValue = new BigInteger(BLINDING_BITS, random);
        // add the fixed blinding component
        blindingValue = blindingValue.add(BLINDING_CONSTANT);
        // replace k with a blinded value that is congruent (mod q)
        k = k.add(q.multiply(blindingValue));

        final BigInteger temp = g.modPow(k, p);
        return temp.mod(q);
    }

    private BigInteger generateS(final BigInteger x, final BigInteger q,
            final BigInteger r, final BigInteger k) throws SignatureException {

        byte[] s2;
        try {
            s2 = md.digest();
        } catch (final RuntimeException re) {
            // Only for RawDSA due to its 20-byte length restriction
            throw new SignatureException(re.getMessage());
        }
        // get the leftmost min(N, outLen) bits of the digest value
        final int nBytes = q.bitLength()/8;
        if (nBytes < s2.length) {
            s2 = Arrays.copyOfRange(s2, 0, nBytes);
        }
        final BigInteger z = new BigInteger(1, s2);
        final BigInteger k1 = k.modInverse(q);

        return x.multiply(r).add(z).multiply(k1).mod(q);
    }

    private BigInteger generateW(final BigInteger p, final BigInteger q,
                         final BigInteger g, final BigInteger s) {
        return s.modInverse(q);
    }

    private BigInteger generateV(final BigInteger y, final BigInteger p,
             final BigInteger q, final BigInteger g, final BigInteger w, final BigInteger r)
             throws SignatureException {

        byte[] s2;
        try {
            s2 = md.digest();
        } catch (final RuntimeException re) {
            // Only for RawDSA due to its 20-byte length restriction
            throw new SignatureException(re.getMessage());
        }
        // get the leftmost min(N, outLen) bits of the digest value
        final int nBytes = q.bitLength()/8;
        if (nBytes < s2.length) {
            s2 = Arrays.copyOfRange(s2, 0, nBytes);
        }
        final BigInteger z = new BigInteger(1, s2);

        final BigInteger u1 = z.multiply(w).mod(q);
        final BigInteger u2 = (r.multiply(w)).mod(q);

        final BigInteger t1 = g.modPow(u1,p);
        final BigInteger t2 = y.modPow(u2,p);
        final BigInteger t3 = t1.multiply(t2);
        final BigInteger t5 = t3.mod(p);
        return t5.mod(q);
    }

    protected BigInteger generateK(final BigInteger q) {
        // Implementation defined in FIPS 186-4 AppendixB.2.1.
        final SecureRandom random = getSigningRandom();
        final byte[] kValue = new byte[(q.bitLength() + 7)/8 + 8];

        random.nextBytes(kValue);
        return new BigInteger(1, kValue).mod(
                q.subtract(BigInteger.ONE)).add(BigInteger.ONE);
    }

    // Use the application-specified SecureRandom Object if provided.
    // Otherwise, use our default SecureRandom Object.
    protected SecureRandom getSigningRandom() {
        if (signingRandom == null) {
            if (appRandom != null) {
                signingRandom = appRandom;
            } else {
                signingRandom = JCAUtil.getSecureRandom();
            }
        }
        return signingRandom;
    }

    /**
     * Return a human readable rendition of the engine.
     */
    @Override
    public String toString() {
        String printable = "DSA Signature";
        if (presetP != null && presetQ != null && presetG != null) {
            printable += "\n\tp: " + Debug.toHexString(presetP);
            printable += "\n\tq: " + Debug.toHexString(presetQ);
            printable += "\n\tg: " + Debug.toHexString(presetG);
        } else {
            printable += "\n\t P, Q or G not initialized.";
        }
        if (presetY != null) {
            printable += "\n\ty: " + Debug.toHexString(presetY);
        }
        if (presetY == null && presetX == null) {
            printable += "\n\tUNINIIALIZED";
        }
        return printable;
    }

    @SuppressWarnings("unused")
    private static void debug(final Exception e) {
        if (debug) {
            e.printStackTrace();
        }
    }

    @SuppressWarnings("unused")
    private static void debug(final String s) {
        if (debug) {
            System.err.println(s);
        }
    }

    /**
     * Standard SHA224withDSA implementation as defined in FIPS186-3.
     */
    public static final class SHA224withDSA extends DSA {
        public SHA224withDSA() throws NoSuchAlgorithmException {
            super(MessageDigest.getInstance("SHA-224"));
        }
    }

    /**
     * Standard SHA256withDSA implementation as defined in FIPS186-3.
     */
    public static final class SHA256withDSA extends DSA {
        public SHA256withDSA() throws NoSuchAlgorithmException {
            super(MessageDigest.getInstance("SHA-256"));
        }
    }

    /**
     * Standard SHA1withDSA implementation.
     */
    public static final class SHA1withDSA extends DSA {
        public SHA1withDSA() throws NoSuchAlgorithmException {
            super(MessageDigest.getInstance("SHA-1"));
        }
    }

    /**
     * RawDSA implementation.
     *
     * RawDSA requires the data to be exactly 20 bytes long. If it is
     * not, a SignatureException is thrown when sign()/verify() is called
     * per JCA spec.
     */
    public static final class RawDSA extends DSA {
        // Internal special-purpose MessageDigest impl for RawDSA
        // Only override whatever methods used
        // NOTE: no clone support
        public static final class NullDigest20 extends MessageDigest {
            // 20 byte digest buffer
            private final byte[] digestBuffer = new byte[20];

            // offset into the buffer; use Integer.MAX_VALUE to indicate
            // out-of-bound condition
            private int ofs = 0;

            protected NullDigest20() {
                super("NullDigest20");
            }
            @Override
            protected void engineUpdate(final byte input) {
                if (ofs == digestBuffer.length) {
                    ofs = Integer.MAX_VALUE;
                } else {
                    digestBuffer[ofs++] = input;
                }
            }
            @Override
            protected void engineUpdate(final byte[] input, final int offset, final int len) {
                if (ofs + len > digestBuffer.length) {
                    ofs = Integer.MAX_VALUE;
                } else {
                    System.arraycopy(input, offset, digestBuffer, ofs, len);
                    ofs += len;
                }
            }
            @Override
            protected final void engineUpdate(final ByteBuffer input) {
                final int inputLen = input.remaining();
                if (ofs + inputLen > digestBuffer.length) {
                    ofs = Integer.MAX_VALUE;
                } else {
                    input.get(digestBuffer, ofs, inputLen);
                    ofs += inputLen;
                }
            }
            @Override
            protected byte[] engineDigest() throws RuntimeException {
                if (ofs != digestBuffer.length) {
                    throw new RuntimeException
                        ("Data for RawDSA must be exactly 20 bytes long");
                }
                reset();
                return digestBuffer;
            }
            @Override
            protected int engineDigest(final byte[] buf, final int offset, final int len)
                throws DigestException {
                if (ofs != digestBuffer.length) {
                    throw new DigestException
                        ("Data for RawDSA must be exactly 20 bytes long");
                }
                if (len < digestBuffer.length) {
                    throw new DigestException
                        ("Output buffer too small; must be at least 20 bytes");
                }
                System.arraycopy(digestBuffer, 0, buf, offset, digestBuffer.length);
                reset();
                return digestBuffer.length;
            }

            @Override
            protected void engineReset() {
                ofs = 0;
            }
            @Override
            protected final int engineGetDigestLength() {
                return digestBuffer.length;
            }
        }

        public RawDSA() throws NoSuchAlgorithmException {
            super(new NullDigest20());
        }
    }
}
