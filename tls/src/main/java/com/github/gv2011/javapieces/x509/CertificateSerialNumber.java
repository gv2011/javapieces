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
package com.github.gv2011.javapieces.x509;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Enumeration;

import com.github.gv2011.javapieces.secutil.DerInputStream;
import com.github.gv2011.javapieces.secutil.DerOutputStream;
import com.github.gv2011.javapieces.secutil.DerValue;



/**
 * This class defines the SerialNumber attribute for the Certificate.
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @see CertAttrSet
 */
public class CertificateSerialNumber implements CertAttrSet<String> {
    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT = "x509.info.serialNumber";

    /**
     * Sub attributes name for this CertAttrSet.
     */
    public static final String NAME = "serialNumber";
    public static final String NUMBER = "number";

    private SerialNumber        serial;

    /**
     * Default constructor for the certificate attribute.
     *
     * @param serial the serial number for the certificate.
     */
    public CertificateSerialNumber(final BigInteger num) {
      serial = new SerialNumber(num);
    }

    /**
     * Default constructor for the certificate attribute.
     *
     * @param serial the serial number for the certificate.
     */
    public CertificateSerialNumber(final int num) {
      serial = new SerialNumber(num);
    }

    /**
     * Create the object, decoding the values from the passed DER stream.
     *
     * @param in the DerInputStream to read the serial number from.
     * @exception IOException on decoding errors.
     */
    public CertificateSerialNumber(final DerInputStream in) throws IOException {
        serial = new SerialNumber(in);
    }

    /**
     * Create the object, decoding the values from the passed stream.
     *
     * @param in the InputStream to read the serial number from.
     * @exception IOException on decoding errors.
     */
    public CertificateSerialNumber(final InputStream in) throws IOException {
        serial = new SerialNumber(in);
    }

    /**
     * Create the object, decoding the values from the passed DerValue.
     *
     * @param val the DER encoded value.
     * @exception IOException on decoding errors.
     */
    public CertificateSerialNumber(final DerValue val) throws IOException {
        serial = new SerialNumber(val);
    }

    /**
     * Return the serial number as user readable string.
     */
    @Override
    public String toString() {
        if (serial == null) return "";
        return (serial.toString());
    }

    /**
     * Encode the serial number in DER form to the stream.
     *
     * @param out the DerOutputStream to marshal the contents to.
     * @exception IOException on errors.
     */
    @Override
    public void encode(final OutputStream out) throws IOException {
        final DerOutputStream tmp = new DerOutputStream();
        serial.encode(tmp);

        out.write(tmp.toByteArray());
    }

    /**
     * Set the attribute value.
     */
    @Override
    public void set(final String name, final Object obj) throws IOException {
        if (!(obj instanceof SerialNumber)) {
            throw new IOException("Attribute must be of type SerialNumber.");
        }
        if (name.equalsIgnoreCase(NUMBER)) {
            serial = (SerialNumber)obj;
        } else {
            throw new IOException("Attribute name not recognized by " +
                                "CertAttrSet:CertificateSerialNumber.");
        }
    }

    /**
     * Get the attribute value.
     */
    @Override
    public SerialNumber get(final String name) throws IOException {
        if (name.equalsIgnoreCase(NUMBER)) {
            return (serial);
        } else {
            throw new IOException("Attribute name not recognized by " +
                                "CertAttrSet:CertificateSerialNumber.");
        }
    }

    /**
     * Delete the attribute value.
     */
    @Override
    public void delete(final String name) throws IOException {
        if (name.equalsIgnoreCase(NUMBER)) {
            serial = null;
        } else {
            throw new IOException("Attribute name not recognized by " +
                                "CertAttrSet:CertificateSerialNumber.");
        }
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    @Override
    public Enumeration<String> getElements() {
        final AttributeNameEnumeration elements = new AttributeNameEnumeration();
        elements.addElement(NUMBER);

        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    @Override
    public String getName() {
        return (NAME);
    }
}
