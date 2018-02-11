/*
 * Copyright (c) 2001, 2013, Oracle and/or its affiliates. All rights reserved.
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

package com.github.gv2011.javapieces.suntls;

import static com.github.gv2011.javapieces.suntls.SunJSSE.cryptoProvider;

import java.math.BigInteger;
import java.security.AccessController;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;
// explicit import to override the Provider class in this package
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.RSAPublicKeySpec;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;

import com.github.gv2011.javapieces.jca.ProviderList;
import com.github.gv2011.javapieces.jca.Providers;
import com.github.gv2011.javapieces.secutil.ECUtil;

/**
 * This class contains a few static methods for interaction with the JCA/JCE
 * to obtain implementations, etc.
 *
 * @author  Andreas Sterbenz
 */
final class JsseJce {

    private final static ProviderList fipsProviderList;

    // Flag indicating whether Kerberos crypto is available.
    // If true, then all the Kerberos-based crypto we need is available.
    private final static boolean kerberosAvailable;
    static {
        boolean temp;
        try {
            AccessController.doPrivileged(
                (PrivilegedExceptionAction<Void>) () -> {
                    // Test for Kerberos using the bootstrap class loader
                    Class.forName("sun.security.krb5.PrincipalName", true,
                            null);
                    return null;
                });
            temp = true;

        } catch (final Exception e) {
            temp = false;
        }
        kerberosAvailable = temp;
    }

    static {
        // force FIPS flag initialization
        // Because isFIPS() is synchronized and cryptoProvider is not modified
        // after it completes, this also eliminates the need for any further
        // synchronization when accessing cryptoProvider
        if (SunJSSE.isFIPS() == false) {
            fipsProviderList = null;
        } else {
            // Setup a ProviderList that can be used by the trust manager
            // during certificate chain validation. All the crypto must be
            // from the FIPS provider, but we also allow the required
            // certificate related services from the SUN provider.
            final Provider sun = Security.getProvider("SUN");
            if (sun == null) {
                throw new RuntimeException
                    ("FIPS mode: SUN provider must be installed");
            }
            final Provider sunCerts = new SunCertificates(sun);
            fipsProviderList = ProviderList.newList(cryptoProvider, sunCerts);
        }
    }

    private static final class SunCertificates extends Provider {
        private static final long serialVersionUID = -3284138292032213752L;

        SunCertificates(final Provider p) {
            super("SunCertificates", 1.8d, "SunJSSE internal");
            AccessController.doPrivileged((PrivilegedAction<Object>) () -> {
                // copy certificate related services from the Sun provider
                for (final Map.Entry<Object,Object> entry : p.entrySet()) {
                    final String key = (String)entry.getKey();
                    if (key.startsWith("CertPathValidator.")
                            || key.startsWith("CertPathBuilder.")
                            || key.startsWith("CertStore.")
                            || key.startsWith("CertificateFactory.")) {
                        put(key, entry.getValue());
                    }
                }
                return null;
            });
        }
    }

    /**
     * JCE transformation string for RSA with PKCS#1 v1.5 padding.
     * Can be used for encryption, decryption, signing, verifying.
     */
    final static String CIPHER_RSA_PKCS1 = "RSA/ECB/PKCS1Padding";
    /**
     * JCE transformation string for the stream cipher RC4.
     */
    final static String CIPHER_RC4 = "RC4";
    /**
     * JCE transformation string for DES in CBC mode without padding.
     */
    final static String CIPHER_DES = "DES/CBC/NoPadding";
    /**
     * JCE transformation string for (3-key) Triple DES in CBC mode
     * without padding.
     */
    final static String CIPHER_3DES = "DESede/CBC/NoPadding";
    /**
     * JCE transformation string for AES in CBC mode
     * without padding.
     */
    final static String CIPHER_AES = "AES/CBC/NoPadding";
    /**
     * JCE transformation string for AES in GCM mode
     * without padding.
     */
    final static String CIPHER_AES_GCM = "AES/GCM/NoPadding";
    /**
     * JCA identifier string for DSA, i.e. a DSA with SHA-1.
     */
    final static String SIGNATURE_DSA = "DSA";
    /**
     * JCA identifier string for ECDSA, i.e. a ECDSA with SHA-1.
     */
    final static String SIGNATURE_ECDSA = "SHA1withECDSA";
    /**
     * JCA identifier string for Raw DSA, i.e. a DSA signature without
     * hashing where the application provides the SHA-1 hash of the data.
     * Note that the standard name is "NONEwithDSA" but we use "RawDSA"
     * for compatibility.
     */
    final static String SIGNATURE_RAWDSA = "RawDSA";
    /**
     * JCA identifier string for Raw ECDSA, i.e. a DSA signature without
     * hashing where the application provides the SHA-1 hash of the data.
     */
    final static String SIGNATURE_RAWECDSA = "NONEwithECDSA";
    /**
     * JCA identifier string for Raw RSA, i.e. a RSA PKCS#1 v1.5 signature
     * without hashing where the application provides the hash of the data.
     * Used for RSA client authentication with a 36 byte hash.
     */
    final static String SIGNATURE_RAWRSA = "NONEwithRSA";
    /**
     * JCA identifier string for the SSL/TLS style RSA Signature. I.e.
     * an signature using RSA with PKCS#1 v1.5 padding signing a
     * concatenation of an MD5 and SHA-1 digest.
     */
    final static String SIGNATURE_SSLRSA = "MD5andSHA1withRSA";

    private JsseJce() {
        // no instantiation of this class
    }

    static boolean isEcAvailable() {
        return EcAvailability.isAvailable;
    }

    static boolean isKerberosAvailable() {
        return kerberosAvailable;
    }

    /**
     * Return an JCE cipher implementation for the specified algorithm.
     */
    static Cipher getCipher(final String transformation)
            throws NoSuchAlgorithmException {
        try {
            if (cryptoProvider == null) {
                return Cipher.getInstance(transformation);
            } else {
                return Cipher.getInstance(transformation, cryptoProvider);
            }
        } catch (final NoSuchPaddingException e) {
            throw new NoSuchAlgorithmException(e);
        }
    }

    /**
     * Return an JCA signature implementation for the specified algorithm.
     * The algorithm string should be one of the constants defined
     * in this class.
     */
    static Signature getSignature(final String algorithm)
            throws NoSuchAlgorithmException {
        if (cryptoProvider == null) {
            return Signature.getInstance(algorithm);
        } else {
            // reference equality
            if (algorithm == SIGNATURE_SSLRSA) {
                // The SunPKCS11 provider currently does not support this
                // special algorithm. We allow a fallback in this case because
                // the SunJSSE implementation does the actual crypto using
                // a NONEwithRSA signature obtained from the cryptoProvider.
                if (cryptoProvider.getService("Signature", algorithm) == null) {
                    // Calling Signature.getInstance() and catching the
                    // exception would be cleaner, but exceptions are a little
                    // expensive. So we check directly via getService().
                    try {
                        return Signature.getInstance(algorithm, "SunJSSE");
                    } catch (final NoSuchProviderException e) {
                        throw new NoSuchAlgorithmException(e);
                    }
                }
            }
            return Signature.getInstance(algorithm, cryptoProvider);
        }
    }

    static KeyGenerator getKeyGenerator(final String algorithm)
            throws NoSuchAlgorithmException {
        if (cryptoProvider == null) {
            return KeyGenerator.getInstance(algorithm);
        } else {
            return KeyGenerator.getInstance(algorithm, cryptoProvider);
        }
    }

    static KeyPairGenerator getKeyPairGenerator(final String algorithm)
            throws NoSuchAlgorithmException {
        if (cryptoProvider == null) {
            return KeyPairGenerator.getInstance(algorithm);
        } else {
            return KeyPairGenerator.getInstance(algorithm, cryptoProvider);
        }
    }

    static KeyAgreement getKeyAgreement(final String algorithm)
            throws NoSuchAlgorithmException {
        if (cryptoProvider == null) {
            return KeyAgreement.getInstance(algorithm);
        } else {
            return KeyAgreement.getInstance(algorithm, cryptoProvider);
        }
    }

    static Mac getMac(final String algorithm)
            throws NoSuchAlgorithmException {
        if (cryptoProvider == null) {
            return Mac.getInstance(algorithm);
        } else {
            return Mac.getInstance(algorithm, cryptoProvider);
        }
    }

    static KeyFactory getKeyFactory(final String algorithm)
            throws NoSuchAlgorithmException {
        if (cryptoProvider == null) {
            return KeyFactory.getInstance(algorithm);
        } else {
            return KeyFactory.getInstance(algorithm, cryptoProvider);
        }
    }

    static AlgorithmParameters getAlgorithmParameters(final String algorithm)
            throws NoSuchAlgorithmException {
        if (cryptoProvider == null) {
            return AlgorithmParameters.getInstance(algorithm);
        } else {
            return AlgorithmParameters.getInstance(algorithm, cryptoProvider);
        }
    }

    static SecureRandom getSecureRandom() throws KeyManagementException {
        if (cryptoProvider == null) {
            return new SecureRandom();
        }
        // Try "PKCS11" first. If that is not supported, iterate through
        // the provider and return the first working implementation.
        try {
            return SecureRandom.getInstance("PKCS11", cryptoProvider);
        } catch (final NoSuchAlgorithmException e) {
            // ignore
        }
        for (final Provider.Service s : cryptoProvider.getServices()) {
            if (s.getType().equals("SecureRandom")) {
                try {
                    return SecureRandom.getInstance(s.getAlgorithm(), cryptoProvider);
                } catch (final NoSuchAlgorithmException ee) {
                    // ignore
                }
            }
        }
        throw new KeyManagementException("FIPS mode: no SecureRandom "
            + " implementation found in provider " + cryptoProvider.getName());
    }

    static MessageDigest getMD5() {
        return getMessageDigest("MD5");
    }

    static MessageDigest getSHA() {
        return getMessageDigest("SHA");
    }

    static MessageDigest getMessageDigest(final String algorithm) {
        try {
            if (cryptoProvider == null) {
                return MessageDigest.getInstance(algorithm);
            } else {
                return MessageDigest.getInstance(algorithm, cryptoProvider);
            }
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException
                        ("Algorithm " + algorithm + " not available", e);
        }
    }

    static int getRSAKeyLength(final PublicKey key) {
        BigInteger modulus;
        if (key instanceof RSAPublicKey) {
            modulus = ((RSAPublicKey)key).getModulus();
        } else {
            final RSAPublicKeySpec spec = getRSAPublicKeySpec(key);
            modulus = spec.getModulus();
        }
        return modulus.bitLength();
    }

    static RSAPublicKeySpec getRSAPublicKeySpec(final PublicKey key) {
        if (key instanceof RSAPublicKey) {
            final RSAPublicKey rsaKey = (RSAPublicKey)key;
            return new RSAPublicKeySpec(rsaKey.getModulus(),
                                        rsaKey.getPublicExponent());
        }
        try {
            final KeyFactory factory = JsseJce.getKeyFactory("RSA");
            return factory.getKeySpec(key, RSAPublicKeySpec.class);
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    static ECParameterSpec getECParameterSpec(final String namedCurveOid) {
        return ECUtil.getECParameterSpec(cryptoProvider, namedCurveOid);
    }

    static String getNamedCurveOid(final ECParameterSpec params) {
        return ECUtil.getCurveName(cryptoProvider, params);
    }

    static ECPoint decodePoint(final byte[] encoded, final EllipticCurve curve)
            throws java.io.IOException {
        return ECUtil.decodePoint(encoded, curve);
    }

    static byte[] encodePoint(final ECPoint point, final EllipticCurve curve) {
        return ECUtil.encodePoint(point, curve);
    }

    // In FIPS mode, set thread local providers; otherwise a no-op.
    // Must be paired with endFipsProvider.
    static Object beginFipsProvider() {
        if (fipsProviderList == null) {
            return null;
        } else {
            return Providers.beginThreadProviderList(fipsProviderList);
        }
    }

    static void endFipsProvider(final Object o) {
        if (fipsProviderList != null) {
            Providers.endThreadProviderList((ProviderList)o);
        }
    }


    // lazy initialization holder class idiom for static default parameters
    //
    // See Effective Java Second Edition: Item 71.
    private static class EcAvailability {
        // Is EC crypto available?
        private final static boolean isAvailable;

        static {
            boolean mediator = true;
            try {
                JsseJce.getSignature(SIGNATURE_ECDSA);
                JsseJce.getSignature(SIGNATURE_RAWECDSA);
                JsseJce.getKeyAgreement("ECDH");
                JsseJce.getKeyFactory("EC");
                JsseJce.getKeyPairGenerator("EC");
                JsseJce.getAlgorithmParameters("EC");
            } catch (final Exception e) {
                mediator = false;
            }

            isAvailable = mediator;
        }
    }
}
