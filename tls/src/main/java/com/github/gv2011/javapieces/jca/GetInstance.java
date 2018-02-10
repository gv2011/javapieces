/*
 * Copyright (c) 2003, 2013, Oracle and/or its affiliates. All rights reserved.
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

package com.github.gv2011.javapieces.jca;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Provider.Service;
import java.util.List;

/**
 * Collection of utility methods to facilitate implementing getInstance()
 * methods in the JCA/JCE/JSSE/... framework.
 *
 * @author  Andreas Sterbenz
 * @since   1.5
 */
public class GetInstance {

    private GetInstance() {
        // empty
    }

    /**
     * Static inner class representing a newly created instance.
     */
    public static final class Instance {
        // public final fields, access directly without accessors
        public final Provider provider;
        public final Object impl;
        private Instance(final Provider provider, final Object impl) {
            this.provider = provider;
            this.impl = impl;
        }
        // Return Provider and implementation as an array as used in the
        // old Security.getImpl() methods.
        public Object[] toArray() {
            return new Object[] {impl, provider};
        }
    }

    public static Service getService(final String type, final String algorithm)
            throws NoSuchAlgorithmException {
        final ProviderList list = Providers.getProviderList();
        final Service s = list.getService(type, algorithm);
        if (s == null) {
            throw new NoSuchAlgorithmException
                    (algorithm + " " + type + " not available");
        }
        return s;
    }

    public static Service getService(final String type, final String algorithm,
            final String provider) throws NoSuchAlgorithmException,
            NoSuchProviderException {
        if ((provider == null) || (provider.length() == 0)) {
            throw new IllegalArgumentException("missing provider");
        }
        final Provider p = Providers.getProviderList().getProvider(provider);
        if (p == null) {
            throw new NoSuchProviderException("no such provider: " + provider);
        }
        final Service s = p.getService(type, algorithm);
        if (s == null) {
            throw new NoSuchAlgorithmException("no such algorithm: "
                + algorithm + " for provider " + provider);
        }
        return s;
    }

    public static Service getService(final String type, final String algorithm,
            final Provider provider) throws NoSuchAlgorithmException {
        if (provider == null) {
            throw new IllegalArgumentException("missing provider");
        }
        final Service s = provider.getService(type, algorithm);
        if (s == null) {
            throw new NoSuchAlgorithmException("no such algorithm: "
                + algorithm + " for provider " + provider.getName());
        }
        return s;
    }

    /**
     * Return a List of all the available Services that implement
     * (type, algorithm). Note that the list is initialized lazily
     * and Provider loading and lookup is only trigered when
     * necessary.
     */
    public static List<Service> getServices(final String type, final String algorithm) {
        final ProviderList list = Providers.getProviderList();
        return list.getServices(type, algorithm);
    }

    /**
     * This method exists for compatibility with JCE only. It will be removed
     * once JCE has been changed to use the replacement method.
     * @deprecated use {@code getServices(List<ServiceId>)} instead
     */
    @Deprecated
    public static List<Service> getServices(final String type,
            final List<String> algorithms) {
        final ProviderList list = Providers.getProviderList();
        return list.getServices(type, algorithms);
    }

    /**
     * Return a List of all the available Services that implement any of
     * the specified algorithms. See getServices(String, String) for detals.
     */
    public static List<Service> getServices(final List<ServiceId> ids) {
        final ProviderList list = Providers.getProviderList();
        return list.getServices(ids);
    }

    /*
     * For all the getInstance() methods below:
     * @param type the type of engine (e.g. MessageDigest)
     * @param clazz the Spi class that the implementation must subclass
     *   (e.g. MessageDigestSpi.class) or null if no superclass check
     *   is required
     * @param algorithm the name of the algorithm (or alias), e.g. MD5
     * @param provider the provider (String or Provider object)
     * @param param the parameter to pass to the Spi constructor
     *   (for CertStores)
     *
     * There are overloaded methods for all the permutations.
     */

    public static Instance getInstance(final String type, final Class<?> clazz,
            final String algorithm) throws NoSuchAlgorithmException {
        // in the almost all cases, the first service will work
        // avoid taking long path if so
        final ProviderList list = Providers.getProviderList();
        final Service firstService = list.getService(type, algorithm);
        if (firstService == null) {
            throw new NoSuchAlgorithmException
                    (algorithm + " " + type + " not available");
        }
        NoSuchAlgorithmException failure;
        try {
            return getInstance(firstService, clazz);
        } catch (final NoSuchAlgorithmException e) {
            failure = e;
        }
        // if we cannot get the service from the preferred provider,
        // fail over to the next
        for (final Service s : list.getServices(type, algorithm)) {
            if (s == firstService) {
                // do not retry initial failed service
                continue;
            }
            try {
                return getInstance(s, clazz);
            } catch (final NoSuchAlgorithmException e) {
                failure = e;
            }
        }
        throw failure;
    }

    public static Instance getInstance(final String type, final Class<?> clazz,
            final String algorithm, final Object param) throws NoSuchAlgorithmException {
        final List<Service> services = getServices(type, algorithm);
        NoSuchAlgorithmException failure = null;
        for (final Service s : services) {
            try {
                return getInstance(s, clazz, param);
            } catch (final NoSuchAlgorithmException e) {
                failure = e;
            }
        }
        if (failure != null) {
            throw failure;
        } else {
            throw new NoSuchAlgorithmException
                    (algorithm + " " + type + " not available");
        }
    }

    public static Instance getInstance(final String type, final Class<?> clazz,
            final String algorithm, final String provider) throws NoSuchAlgorithmException,
            NoSuchProviderException {
        return getInstance(getService(type, algorithm, provider), clazz);
    }

    public static Instance getInstance(final String type, final Class<?> clazz,
            final String algorithm, final Object param, final String provider)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        return getInstance(getService(type, algorithm, provider), clazz, param);
    }

    public static Instance getInstance(final String type, final Class<?> clazz,
            final String algorithm, final Provider provider)
            throws NoSuchAlgorithmException {
        return getInstance(getService(type, algorithm, provider), clazz);
    }

    public static Instance getInstance(final String type, final Class<?> clazz,
            final String algorithm, final Object param, final Provider provider)
            throws NoSuchAlgorithmException {
        return getInstance(getService(type, algorithm, provider), clazz, param);
    }

    /*
     * The two getInstance() methods below take a service. They are
     * intended for classes that cannot use the standard methods, e.g.
     * because they implement delayed provider selection like the
     * Signature class.
     */

    public static Instance getInstance(final Service s, final Class<?> clazz)
            throws NoSuchAlgorithmException {
        final Object instance = s.newInstance(null);
        checkSuperClass(s, instance.getClass(), clazz);
        return new Instance(s.getProvider(), instance);
    }

    public static Instance getInstance(final Service s, final Class<?> clazz,
            final Object param) throws NoSuchAlgorithmException {
        final Object instance = s.newInstance(param);
        checkSuperClass(s, instance.getClass(), clazz);
        return new Instance(s.getProvider(), instance);
    }

    /**
     * Check is subClass is a subclass of superClass. If not,
     * throw a NoSuchAlgorithmException.
     */
    public static void checkSuperClass(final Service s, final Class<?> subClass,
            final Class<?> superClass) throws NoSuchAlgorithmException {
        if (superClass == null) {
            return;
        }
        if (superClass.isAssignableFrom(subClass) == false) {
            throw new NoSuchAlgorithmException
                ("class configured for " + s.getType() + ": "
                + s.getClassName() + " not a " + s.getType());
        }
    }

}
