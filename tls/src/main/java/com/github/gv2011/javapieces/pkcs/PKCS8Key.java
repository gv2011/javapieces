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

package com.github.gv2011.javapieces.pkcs;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyRep;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Properties;

import com.github.gv2011.javapieces.secutil.Debug;
import com.github.gv2011.javapieces.secutil.DerOutputStream;
import com.github.gv2011.javapieces.secutil.DerValue;
import com.github.gv2011.javapieces.x509.AlgorithmId;



/**
 * Holds a PKCS#8 key, for example a private key
 *
 * @author Dave Brownell
 * @author Benjamin Renaud
 */
public class PKCS8Key implements PrivateKey {

    /** use serialVersionUID from JDK 1.1. for interoperability */
    private static final long serialVersionUID = -3836890099307167124L;

    /* The algorithm information (name, parameters, etc). */
    protected AlgorithmId algid;

    /* The key bytes, without the algorithm information */
    protected byte[] key;

    /* The encoded for the key. */
    protected byte[] encodedKey;

    /* The version for this key */
    public static final BigInteger version = BigInteger.ZERO;

    /**
     * Default constructor.  The key constructed must have its key
     * and algorithm initialized before it may be used, for example
     * by using <code>decode</code>.
     */
    public PKCS8Key() { }

    /*
     * Build and initialize as a "default" key.  All PKCS#8 key
     * data is stored and transmitted losslessly, but no knowledge
     * about this particular algorithm is available.
     */
    @SuppressWarnings("unused")
    private PKCS8Key (final AlgorithmId algid, final byte key [])
    throws InvalidKeyException {
        this.algid = algid;
        this.key = key;
        encode();
    }

    /*
     * Binary backwards compatibility. New uses should call parseKey().
     */
    public static PKCS8Key parse (final DerValue in) throws IOException {
        PrivateKey key;

        key = parseKey(in);
        if (key instanceof PKCS8Key)
            return (PKCS8Key)key;

        throw new IOException("Provider did not return PKCS8Key");
    }

    /**
     * Construct PKCS#8 subject public key from a DER value.  If
     * the runtime environment is configured with a specific class for
     * this kind of key, a subclass is returned.  Otherwise, a generic
     * PKCS8Key object is returned.
     *
     * <P>This mechanism gurantees that keys (and algorithms) may be
     * freely manipulated and transferred, without risk of losing
     * information.  Also, when a key (or algorithm) needs some special
     * handling, that specific need can be accomodated.
     *
     * @param in the DER-encoded SubjectPublicKeyInfo value
     * @exception IOException on data format errors
     */
    public static PrivateKey parseKey (final DerValue in) throws IOException
    {
        AlgorithmId algorithm;
        PrivateKey privKey;

        if (in.tag != DerValue.tag_Sequence)
            throw new IOException ("corrupt private key");

        final BigInteger parsedVersion = in.data.getBigInteger();
        if (!version.equals(parsedVersion)) {
            throw new IOException("version mismatch: (supported: " +
                                  Debug.toHexString(version) +
                                  ", parsed: " +
                                  Debug.toHexString(parsedVersion));
        }

        algorithm = AlgorithmId.parse (in.data.getDerValue ());

        try {
            privKey = buildPKCS8Key (algorithm, in.data.getOctetString ());

        } catch (final InvalidKeyException e) {
            throw new IOException("corrupt private key");
        }

        if (in.data.available () != 0)
            throw new IOException ("excess private key");
        return privKey;
    }

    /**
     * Parse the key bits.  This may be redefined by subclasses to take
     * advantage of structure within the key.  For example, RSA public
     * keys encapsulate two unsigned integers (modulus and exponent) as
     * DER values within the <code>key</code> bits; Diffie-Hellman and
     * DSS/DSA keys encapsulate a single unsigned integer.
     *
     * <P>This function is called when creating PKCS#8 SubjectPublicKeyInfo
     * values using the PKCS8Key member functions, such as <code>parse</code>
     * and <code>decode</code>.
     *
     * @exception IOException if a parsing error occurs.
     * @exception InvalidKeyException if the key encoding is invalid.
     */
    protected void parseKeyBits () throws IOException, InvalidKeyException {
        encode();
    }

    /*
     * Factory interface, building the kind of key associated with this
     * specific algorithm ID or else returning this generic base class.
     * See the description above.
     */
    static PrivateKey buildPKCS8Key (final AlgorithmId algid, final byte[] key)
    throws IOException, InvalidKeyException
    {
        /*
         * Use the algid and key parameters to produce the ASN.1 encoding
         * of the key, which will then be used as the input to the
         * key factory.
         */
        final DerOutputStream pkcs8EncodedKeyStream = new DerOutputStream();
        encode(pkcs8EncodedKeyStream, algid, key);
        final PKCS8EncodedKeySpec pkcs8KeySpec
            = new PKCS8EncodedKeySpec(pkcs8EncodedKeyStream.toByteArray());

        try {
            // Instantiate the key factory of the appropriate algorithm
            final KeyFactory keyFac = KeyFactory.getInstance(algid.getName());

            // Generate the private key
            return keyFac.generatePrivate(pkcs8KeySpec);
        } catch (final NoSuchAlgorithmException e) {
            // Return generic PKCS8Key with opaque key data (see below)
        } catch (final InvalidKeySpecException e) {
            // Return generic PKCS8Key with opaque key data (see below)
        }

        /*
         * Try again using JDK1.1-style for backwards compatibility.
         */
        String classname = "";
        try {
            @SuppressWarnings("unused")
            final Properties props;
            @SuppressWarnings("unused")
            final String keytype;
            Provider sunProvider;

            sunProvider = Security.getProvider("SUN");
            if (sunProvider == null)
                throw new InstantiationException();
            classname = sunProvider.getProperty("PrivateKey.PKCS#8." +
              algid.getName());
            if (classname == null) {
                throw new InstantiationException();
            }

            Class<?> keyClass = null;
            try {
                keyClass = Class.forName(classname);
            } catch (final ClassNotFoundException e) {
                final ClassLoader cl = ClassLoader.getSystemClassLoader();
                if (cl != null) {
                    keyClass = cl.loadClass(classname);
                }
            }

            Object      inst = null;
            PKCS8Key    result;

            if (keyClass != null)
                inst = keyClass.newInstance();
            if (inst instanceof PKCS8Key) {
                result = (PKCS8Key) inst;
                result.algid = algid;
                result.key = key;
                result.parseKeyBits();
                return result;
            }
        } catch (final ClassNotFoundException e) {
        } catch (final InstantiationException e) {
        } catch (final IllegalAccessException e) {
            // this should not happen.
            throw new IOException (classname + " [internal error]");
        }

        final PKCS8Key result = new PKCS8Key();
        result.algid = algid;
        result.key = key;
        return result;
    }

    /**
     * Returns the algorithm to be used with this key.
     */
    @Override
    public String getAlgorithm() {
        return algid.getName();
    }

    /**
     * Returns the algorithm ID to be used with this key.
     */
    public AlgorithmId  getAlgorithmId () { return algid; }

    /**
     * PKCS#8 sequence on the DER output stream.
     */
    public final void encode(final DerOutputStream out) throws IOException
    {
        encode(out, algid, key);
    }

    /**
     * Returns the DER-encoded form of the key as a byte array.
     */
    @Override
    public synchronized byte[] getEncoded() {
        byte[] result = null;
        try {
            result = encode();
        } catch (final InvalidKeyException e) {
        }
        return result;
    }

    /**
     * Returns the format for this key: "PKCS#8"
     */
    @Override
    public String getFormat() {
        return "PKCS#8";
    }

    /**
     * Returns the DER-encoded form of the key as a byte array.
     *
     * @exception InvalidKeyException if an encoding error occurs.
     */
    public byte[] encode() throws InvalidKeyException {
        if (encodedKey == null) {
            try {
                DerOutputStream out;

                out = new DerOutputStream ();
                encode (out);
                encodedKey = out.toByteArray();

            } catch (final IOException e) {
                throw new InvalidKeyException ("IOException : " +
                                               e.getMessage());
            }
        }
        return encodedKey.clone();
    }

    /**
     * Initialize an PKCS8Key object from an input stream.  The data
     * on that input stream must be encoded using DER, obeying the
     * PKCS#8 format: a sequence consisting of a version, an algorithm
     * ID and a bit string which holds the key.  (That bit string is
     * often used to encapsulate another DER encoded sequence.)
     *
     * <P>Subclasses should not normally redefine this method; they should
     * instead provide a <code>parseKeyBits</code> method to parse any
     * fields inside the <code>key</code> member.
     *
     * @param in an input stream with a DER-encoded PKCS#8
     * SubjectPublicKeyInfo value
     *
     * @exception InvalidKeyException if a parsing error occurs.
     */
    public void decode(final InputStream in) throws InvalidKeyException
    {
        DerValue        val;

        try {
            val = new DerValue (in);
            if (val.tag != DerValue.tag_Sequence)
                throw new InvalidKeyException ("invalid key format");


            final BigInteger version = val.data.getBigInteger();
            if (!version.equals(PKCS8Key.version)) {
                throw new IOException("version mismatch: (supported: " +
                                      Debug.toHexString(PKCS8Key.version) +
                                      ", parsed: " +
                                      Debug.toHexString(version));
            }
            algid = AlgorithmId.parse (val.data.getDerValue ());
            key = val.data.getOctetString ();
            parseKeyBits ();

            if (val.data.available () != 0)  {
                // OPTIONAL attributes not supported yet
            }

        } catch (final IOException e) {
            // e.printStackTrace ();
            throw new InvalidKeyException("IOException : " +
                                          e.getMessage());
        }
    }

    public void decode(final byte[] encodedKey) throws InvalidKeyException {
        decode(new ByteArrayInputStream(encodedKey));
    }

    protected Object writeReplace() throws java.io.ObjectStreamException {
        return new KeyRep(KeyRep.Type.PRIVATE,
                        getAlgorithm(),
                        getFormat(),
                        getEncoded());
    }

    /**
     * Serialization read ... PKCS#8 keys serialize as
     * themselves, and they're parsed when they get read back.
     */
    private void readObject (final ObjectInputStream stream)
    throws IOException {

        try {
            decode(stream);

        } catch (final InvalidKeyException e) {
            e.printStackTrace();
            throw new IOException("deserialized key is invalid: " +
                                  e.getMessage());
        }
    }

    /*
     * Produce PKCS#8 encoding from algorithm id and key material.
     */
    static void encode(final DerOutputStream out, final AlgorithmId algid, final byte[] key)
        throws IOException {
            final DerOutputStream tmp = new DerOutputStream();
            tmp.putInteger(version);
            algid.encode(tmp);
            tmp.putOctetString(key);
            out.write(DerValue.tag_Sequence, tmp);
    }

    /**
     * Compares two private keys. This returns false if the object with which
     * to compare is not of type <code>Key</code>.
     * Otherwise, the encoding of this key object is compared with the
     * encoding of the given key object.
     *
     * @param object the object with which to compare
     * @return <code>true</code> if this key has the same encoding as the
     * object argument; <code>false</code> otherwise.
     */
    @Override
    public boolean equals(final Object object) {
        if (this == object) {
            return true;
        }

        if (object instanceof Key) {

            // this encoding
            byte[] b1;
            if (encodedKey != null) {
                b1 = encodedKey;
            } else {
                b1 = getEncoded();
            }

            // that encoding
            final byte[] b2 = ((Key)object).getEncoded();

            // time-constant comparison
            return MessageDigest.isEqual(b1, b2);
        }
        return false;
    }

    /**
     * Calculates a hash code value for this object. Objects
     * which are equal will also have the same hashcode.
     */
    @Override
    public int hashCode() {
        int retval = 0;
        final byte[] b1 = getEncoded();

        for (int i = 1; i < b1.length; i++) {
            retval += b1[i] * i;
        }
        return(retval);
    }
}
