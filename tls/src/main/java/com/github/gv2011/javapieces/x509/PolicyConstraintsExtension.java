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
import java.io.OutputStream;
import java.util.Enumeration;

import com.github.gv2011.javapieces.secutil.DerInputStream;
import com.github.gv2011.javapieces.secutil.DerOutputStream;
import com.github.gv2011.javapieces.secutil.DerValue;



/**
 * This class defines the certificate extension which specifies the
 * Policy constraints.
 * <p>
 * The policy constraints extension can be used in certificates issued
 * to CAs. The policy constraints extension constrains path validation
 * in two ways. It can be used to prohibit policy mapping or require
 * that each certificate in a path contain an acceptable policy
 * identifier.<p>
 * The ASN.1 syntax for this is (IMPLICIT tagging is defined in the
 * module definition):
 * <pre>
 * PolicyConstraints ::= SEQUENCE {
 *     requireExplicitPolicy [0] SkipCerts OPTIONAL,
 *     inhibitPolicyMapping  [1] SkipCerts OPTIONAL
 * }
 * SkipCerts ::= INTEGER (0..MAX)
 * </pre>
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @see Extension
 * @see CertAttrSet
 */
public class PolicyConstraintsExtension extends Extension
implements CertAttrSet<String> {
    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT = "x509.info.extensions.PolicyConstraints";
    /**
     * Attribute names.
     */
    public static final String NAME = "PolicyConstraints";
    public static final String REQUIRE = "require";
    public static final String INHIBIT = "inhibit";

    private static final byte TAG_REQUIRE = 0;
    private static final byte TAG_INHIBIT = 1;

    private int require = -1;
    private int inhibit = -1;

    // Encode this extension value.
    private void encodeThis() throws IOException {
        if (require == -1 && inhibit == -1) {
            extensionValue = null;
            return;
        }
        final DerOutputStream tagged = new DerOutputStream();
        @SuppressWarnings("resource")
        final DerOutputStream seq = new DerOutputStream();

        if (require != -1) {
            final DerOutputStream tmp = new DerOutputStream();
            tmp.putInteger(require);
            tagged.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT,
                         false, TAG_REQUIRE), tmp);
        }
        if (inhibit != -1) {
            final DerOutputStream tmp = new DerOutputStream();
            tmp.putInteger(inhibit);
            tagged.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT,
                         false, TAG_INHIBIT), tmp);
        }
        seq.write(DerValue.tag_Sequence, tagged);
        extensionValue = seq.toByteArray();
    }

    /**
     * Create a PolicyConstraintsExtension object with both
     * require explicit policy and inhibit policy mapping. The
     * extension is marked non-critical.
     *
     * @param require require explicit policy (-1 for optional).
     * @param inhibit inhibit policy mapping (-1 for optional).
     */
    public PolicyConstraintsExtension(final int require, final int inhibit)
    throws IOException {
        this(Boolean.FALSE, require, inhibit);
    }

    /**
     * Create a PolicyConstraintsExtension object with specified
     * criticality and both require explicit policy and inhibit
     * policy mapping.
     *
     * @param critical true if the extension is to be treated as critical.
     * @param require require explicit policy (-1 for optional).
     * @param inhibit inhibit policy mapping (-1 for optional).
     */
    public PolicyConstraintsExtension(final Boolean critical, final int require, final int inhibit)
    throws IOException {
        this.require = require;
        this.inhibit = inhibit;
        extensionId = PKIXExtensions.PolicyConstraints_Id;
        this.critical = critical.booleanValue();
        encodeThis();
    }

    /**
     * Create the extension from its DER encoded value and criticality.
     *
     * @param critical true if the extension is to be treated as critical.
     * @param value an array of DER encoded bytes of the actual value.
     * @exception ClassCastException if value is not an array of bytes
     * @exception IOException on error.
     */
    public PolicyConstraintsExtension(final Boolean critical, final Object value)
    throws IOException {
        extensionId = PKIXExtensions.PolicyConstraints_Id;
        this.critical = critical.booleanValue();

        extensionValue = (byte[]) value;
        final DerValue val = new DerValue(extensionValue);
        if (val.tag != DerValue.tag_Sequence) {
            throw new IOException("Sequence tag missing for PolicyConstraint.");
        }
        final DerInputStream in = val.data;
        while (in != null && in.available() != 0) {
            final DerValue next = in.getDerValue();

            if (next.isContextSpecific(TAG_REQUIRE) && !next.isConstructed()) {
                if (require != -1)
                    throw new IOException("Duplicate requireExplicitPolicy" +
                          "found in the PolicyConstraintsExtension");
                next.resetTag(DerValue.tag_Integer);
                require = next.getInteger();

            } else if (next.isContextSpecific(TAG_INHIBIT) &&
                       !next.isConstructed()) {
                if (inhibit != -1)
                    throw new IOException("Duplicate inhibitPolicyMapping" +
                          "found in the PolicyConstraintsExtension");
                next.resetTag(DerValue.tag_Integer);
                inhibit = next.getInteger();
            } else
                throw new IOException("Invalid encoding of PolicyConstraint");
        }
    }

    /**
     * Return the extension as user readable string.
     */
    @Override
    public String toString() {
        String s;
        s = super.toString() + "PolicyConstraints: [" + "  Require: ";
        if (require == -1)
            s += "unspecified;";
        else
            s += require + ";";
        s += "\tInhibit: ";
        if (inhibit == -1)
            s += "unspecified";
        else
            s += inhibit;
        s += " ]\n";
        return s;
    }

    /**
     * Write the extension to the DerOutputStream.
     *
     * @param out the DerOutputStream to write the extension to.
     * @exception IOException on encoding errors.
     */
    @Override
    public void encode(final OutputStream out) throws IOException {
        final DerOutputStream tmp = new DerOutputStream();
        if (extensionValue == null) {
          extensionId = PKIXExtensions.PolicyConstraints_Id;
          critical = false;
          encodeThis();
        }
        super.encode(tmp);
        out.write(tmp.toByteArray());
    }

    /**
     * Set the attribute value.
     */
    @Override
    public void set(final String name, final Object obj) throws IOException {
        if (!(obj instanceof Integer)) {
            throw new IOException("Attribute value should be of type Integer.");
        }
        if (name.equalsIgnoreCase(REQUIRE)) {
            require = ((Integer)obj).intValue();
        } else if (name.equalsIgnoreCase(INHIBIT)) {
            inhibit = ((Integer)obj).intValue();
        } else {
          throw new IOException("Attribute name " + "[" + name + "]" +
                                " not recognized by " +
                                "CertAttrSet:PolicyConstraints.");
        }
        encodeThis();
    }

    /**
     * Get the attribute value.
     */
    @Override
    public Integer get(final String name) throws IOException {
        if (name.equalsIgnoreCase(REQUIRE)) {
            return new Integer(require);
        } else if (name.equalsIgnoreCase(INHIBIT)) {
            return new Integer(inhibit);
        } else {
          throw new IOException("Attribute name not recognized by " +
                                "CertAttrSet:PolicyConstraints.");
        }
    }

    /**
     * Delete the attribute value.
     */
    @Override
    public void delete(final String name) throws IOException {
        if (name.equalsIgnoreCase(REQUIRE)) {
            require = -1;
        } else if (name.equalsIgnoreCase(INHIBIT)) {
            inhibit = -1;
        } else {
          throw new IOException("Attribute name not recognized by " +
                                "CertAttrSet:PolicyConstraints.");
        }
        encodeThis();
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    @Override
    public Enumeration<String> getElements() {
        final AttributeNameEnumeration elements = new AttributeNameEnumeration();
        elements.addElement(REQUIRE);
        elements.addElement(INHIBIT);

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
