/*
 * Copyright (c) 2007, 2011, Oracle and/or its affiliates. All rights reserved.
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
import java.io.OutputStream;
import java.util.Date;
import java.util.Enumeration;

import com.github.gv2011.javapieces.secutil.DerOutputStream;
import com.github.gv2011.javapieces.secutil.DerValue;



/**
 * From RFC 3280:
 * <p>
 * The invalidity date is a non-critical CRL entry extension that
 * provides the date on which it is known or suspected that the private
 * key was compromised or that the certificate otherwise became invalid.
 * This date may be earlier than the revocation date in the CRL entry,
 * which is the date at which the CA processed the revocation.  When a
 * revocation is first posted by a CRL issuer in a CRL, the invalidity
 * date may precede the date of issue of earlier CRLs, but the
 * revocation date SHOULD NOT precede the date of issue of earlier CRLs.
 * Whenever this information is available, CRL issuers are strongly
 * encouraged to share it with CRL users.
 * <p>
 * The GeneralizedTime values included in this field MUST be expressed
 * in Greenwich Mean Time (Zulu), and MUST be specified and interpreted
 * as defined in section 4.1.2.5.2.
 * <pre>
 * id-ce-invalidityDate OBJECT IDENTIFIER ::= { id-ce 24 }
 *
 * invalidityDate ::=  GeneralizedTime
 * </pre>
 *
 * @author Sean Mullan
 */
public class InvalidityDateExtension extends Extension
    implements CertAttrSet<String> {

    /**
     * Attribute name and Reason codes
     */
    public static final String NAME = "InvalidityDate";
    public static final String DATE = "date";

    private Date date;

    private void encodeThis() throws IOException {
        if (date == null) {
            extensionValue = null;
            return;
        }
        @SuppressWarnings("resource")
        final DerOutputStream dos = new DerOutputStream();
        dos.putGeneralizedTime(date);
        extensionValue = dos.toByteArray();
    }

    /**
     * Create a InvalidityDateExtension with the passed in date.
     * Criticality automatically set to false.
     *
     * @param date the invalidity date
     */
    public InvalidityDateExtension(final Date date) throws IOException {
        this(false, date);
    }

    /**
     * Create a InvalidityDateExtension with the passed in date.
     *
     * @param critical true if the extension is to be treated as critical.
     * @param date the invalidity date
     */
    public InvalidityDateExtension(final boolean critical, final Date date)
    throws IOException {
        extensionId = PKIXExtensions.InvalidityDate_Id;
        this.critical = critical;
        this.date = date;
        encodeThis();
    }

    /**
     * Create the extension from the passed DER encoded value of the same.
     *
     * @param critical true if the extension is to be treated as critical.
     * @param value an array of DER encoded bytes of the actual value.
     * @exception ClassCastException if value is not an array of bytes
     * @exception IOException on error.
     */
    public InvalidityDateExtension(final Boolean critical, final Object value)
    throws IOException {
        extensionId = PKIXExtensions.InvalidityDate_Id;
        this.critical = critical.booleanValue();
        extensionValue = (byte[]) value;
        final DerValue val = new DerValue(extensionValue);
        date = val.getGeneralizedTime();
    }

    /**
     * Set the attribute value.
     */
    @Override
    public void set(final String name, final Object obj) throws IOException {
        if (!(obj instanceof Date)) {
            throw new IOException("Attribute must be of type Date.");
        }
        if (name.equalsIgnoreCase(DATE)) {
            date = (Date) obj;
        } else {
            throw new IOException
                ("Name not supported by InvalidityDateExtension");
        }
        encodeThis();
    }

    /**
     * Get the attribute value.
     */
    @Override
    public Date get(final String name) throws IOException {
        if (name.equalsIgnoreCase(DATE)) {
            if (date == null) {
                return null;
            } else {
                return (new Date(date.getTime()));    // clone
            }
        } else {
            throw new IOException
                ("Name not supported by InvalidityDateExtension");
        }
    }

    /**
     * Delete the attribute value.
     */
    @Override
    public void delete(final String name) throws IOException {
        if (name.equalsIgnoreCase(DATE)) {
            date = null;
        } else {
            throw new IOException
                ("Name not supported by InvalidityDateExtension");
        }
        encodeThis();
    }

    /**
     * Returns a printable representation of the Invalidity Date.
     */
    @Override
    public String toString() {
        return super.toString() + "    Invalidity Date: " + String.valueOf(date);
    }

    /**
     * Write the extension to the DerOutputStream.
     *
     * @param out the DerOutputStream to write the extension to
     * @exception IOException on encoding errors
     */
    @Override
    public void encode(final OutputStream out) throws IOException {
        final DerOutputStream  tmp = new DerOutputStream();

        if (extensionValue == null) {
            extensionId = PKIXExtensions.InvalidityDate_Id;
            critical = false;
            encodeThis();
        }
        super.encode(tmp);
        out.write(tmp.toByteArray());
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    @Override
    public Enumeration<String> getElements() {
        final AttributeNameEnumeration elements = new AttributeNameEnumeration();
        elements.addElement(DATE);

        return elements.elements();
    }

    /**
     * Return the name of this attribute.
     */
    @Override
    public String getName() {
        return NAME;
    }

    public static InvalidityDateExtension toImpl(final java.security.cert.Extension ext)
        throws IOException {
        if (ext instanceof InvalidityDateExtension) {
            return (InvalidityDateExtension) ext;
        } else {
            return new InvalidityDateExtension
                (Boolean.valueOf(ext.isCritical()), ext.getValue());
        }
    }
}
