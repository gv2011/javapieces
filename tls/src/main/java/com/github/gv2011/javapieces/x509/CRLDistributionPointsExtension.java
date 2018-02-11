/*
 * Copyright (c) 2002, 2011, Oracle and/or its affiliates. All rights reserved.
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
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import com.github.gv2011.javapieces.secutil.DerOutputStream;
import com.github.gv2011.javapieces.secutil.DerValue;
import com.github.gv2011.javapieces.secutil.ObjectIdentifier;





/**
 * Represent the CRL Distribution Points Extension (OID = 2.5.29.31).
 * <p>
 * The CRL distribution points extension identifies how CRL information
 * is obtained.  The extension SHOULD be non-critical, but the PKIX profile
 * recommends support for this extension by CAs and applications.
 * <p>
 * For PKIX, if the cRLDistributionPoints extension contains a
 * DistributionPointName of type URI, the following semantics MUST be
 * assumed: the URI is a pointer to the current CRL for the associated
 * reasons and will be issued by the associated cRLIssuer.  The
 * expected values for the URI conform to the following rules.  The
 * name MUST be a non-relative URL, and MUST follow the URL syntax and
 * encoding rules specified in [RFC 1738].  The name must include both
 * a scheme (e.g., "http" or "ftp") and a scheme-specific-part.  The
 * scheme- specific-part must include a fully qualified domain name or
 * IP address as the host.  As specified in [RFC 1738], the scheme
 * name is not case-sensitive (e.g., "http" is equivalent to "HTTP").
 * The host part is also not case-sensitive, but other components of
 * the scheme-specific-part may be case-sensitive. When comparing
 * URIs, conforming implementations MUST compare the scheme and host
 * without regard to case, but assume the remainder of the
 * scheme-specific-part is case sensitive.  Processing rules for other
 * values are not defined by this specification.  If the
 * distributionPoint omits reasons, the CRL MUST include revocations
 * for all reasons. If the distributionPoint omits cRLIssuer, the CRL
 * MUST be issued by the CA that issued the certificate.
 * <p>
 * The ASN.1 definition for this is:
 * <pre>
 * id-ce-cRLDistributionPoints OBJECT IDENTIFIER ::=  { id-ce 31 }
 *
 * cRLDistributionPoints ::= {
 *      CRLDistPointsSyntax }
 *
 * CRLDistPointsSyntax ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
 * </pre>
 * <p>
 * @author Anne Anderson
 * @author Andreas Sterbenz
 * @since 1.4.2
 * @see DistributionPoint
 * @see Extension
 * @see CertAttrSet
 */
public class CRLDistributionPointsExtension extends Extension
        implements CertAttrSet<String> {

    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT =
                                "x509.info.extensions.CRLDistributionPoints";

    /**
     * Attribute name.
     */
    public static final String NAME = "CRLDistributionPoints";
    public static final String POINTS = "points";

    /**
     * The List of DistributionPoint objects.
     */
    private List<DistributionPoint> distributionPoints;

    private final String extensionName;

    /**
     * Create a CRLDistributionPointsExtension from a List of
     * DistributionPoint; the criticality is set to false.
     *
     * @param distributionPoints the list of distribution points
     * @throws IOException on error
     */
    public CRLDistributionPointsExtension(
        final List<DistributionPoint> distributionPoints) throws IOException {

        this(false, distributionPoints);
    }

    /**
     * Create a CRLDistributionPointsExtension from a List of
     * DistributionPoint.
     *
     * @param isCritical the criticality setting.
     * @param distributionPoints the list of distribution points
     * @throws IOException on error
     */
    public CRLDistributionPointsExtension(final boolean isCritical,
        final List<DistributionPoint> distributionPoints) throws IOException {

        this(PKIXExtensions.CRLDistributionPoints_Id, isCritical,
            distributionPoints, NAME);
    }

    /**
     * Creates the extension (also called by the subclass).
     */
    protected CRLDistributionPointsExtension(final ObjectIdentifier extensionId,
        final boolean isCritical, final List<DistributionPoint> distributionPoints,
            final String extensionName) throws IOException {

        this.extensionId = extensionId;
        critical = isCritical;
        this.distributionPoints = distributionPoints;
        encodeThis();
        this.extensionName = extensionName;
    }

    /**
     * Create the extension from the passed DER encoded value of the same.
     *
     * @param critical true if the extension is to be treated as critical.
     * @param value Array of DER encoded bytes of the actual value.
     * @exception IOException on error.
     */
    public CRLDistributionPointsExtension(final Boolean critical, final Object value)
            throws IOException {
        this(PKIXExtensions.CRLDistributionPoints_Id, critical, value, NAME);
    }

    /**
     * Creates the extension (also called by the subclass).
     */
    protected CRLDistributionPointsExtension(final ObjectIdentifier extensionId,
        final Boolean critical, final Object value, final String extensionName)
            throws IOException {

        this.extensionId = extensionId;
        this.critical = critical.booleanValue();

        if (!(value instanceof byte[])) {
            throw new IOException("Illegal argument type");
        }

        extensionValue = (byte[])value;
        final DerValue val = new DerValue(extensionValue);
        if (val.tag != DerValue.tag_Sequence) {
            throw new IOException("Invalid encoding for " + extensionName +
                                  " extension.");
        }
        distributionPoints = new ArrayList<>();
        while (val.data.available() != 0) {
            final DerValue seq = val.data.getDerValue();
            final DistributionPoint point = new DistributionPoint(seq);
            distributionPoints.add(point);
        }
        this.extensionName = extensionName;
    }

    /**
     * Return the name of this attribute.
     */
    @Override
    public String getName() {
        return extensionName;
    }

    /**
     * Write the extension to the DerOutputStream.
     *
     * @param out the DerOutputStream to write the extension to.
     * @exception IOException on encoding errors.
     */
    @Override
    public void encode(final OutputStream out) throws IOException {
        encode(out, PKIXExtensions.CRLDistributionPoints_Id, false);
    }

    /**
     * Write the extension to the DerOutputStream.
     * (Also called by the subclass)
     */
    protected void encode(final OutputStream out, final ObjectIdentifier extensionId,
        final boolean isCritical) throws IOException {

        final DerOutputStream tmp = new DerOutputStream();
        if (extensionValue == null) {
            this.extensionId = extensionId;
            critical = isCritical;
            encodeThis();
        }
        super.encode(tmp);
        out.write(tmp.toByteArray());
    }

    /**
     * Set the attribute value.
     */
    @Override
    @SuppressWarnings("unchecked") // Checked with instanceof
    public void set(final String name, final Object obj) throws IOException {
        if (name.equalsIgnoreCase(POINTS)) {
            if (!(obj instanceof List)) {
                throw new IOException("Attribute value should be of type List.");
            }
            distributionPoints = (List<DistributionPoint>)obj;
        } else {
            throw new IOException("Attribute name [" + name +
                                "] not recognized by " +
                                "CertAttrSet:" + extensionName + ".");
        }
        encodeThis();
    }

    /**
     * Get the attribute value.
     */
    @Override
    public List<DistributionPoint> get(final String name) throws IOException {
        if (name.equalsIgnoreCase(POINTS)) {
            return distributionPoints;
        } else {
            throw new IOException("Attribute name [" + name +
                                "] not recognized by " +
                                "CertAttrSet:" + extensionName + ".");
        }
    }

    /**
     * Delete the attribute value.
     */
    @Override
    public void delete(final String name) throws IOException {
        if (name.equalsIgnoreCase(POINTS)) {
            distributionPoints =
                    Collections.<DistributionPoint>emptyList();
        } else {
            throw new IOException("Attribute name [" + name +
                                  "] not recognized by " +
                                  "CertAttrSet:" + extensionName + '.');
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
        elements.addElement(POINTS);
        return elements.elements();
    }

     // Encode this extension value
    private void encodeThis() throws IOException {
        if (distributionPoints.isEmpty()) {
            extensionValue = null;
        } else {
            final DerOutputStream pnts = new DerOutputStream();
            for (final DistributionPoint point : distributionPoints) {
                point.encode(pnts);
            }
            @SuppressWarnings("resource")
            final DerOutputStream seq = new DerOutputStream();
            seq.write(DerValue.tag_Sequence, pnts);
            extensionValue = seq.toByteArray();
        }
    }

    /**
     * Return the extension as user readable string.
     */
    @Override
    public String toString() {
        return super.toString() + extensionName + " [\n  "
               + distributionPoints + "]\n";
    }

}
