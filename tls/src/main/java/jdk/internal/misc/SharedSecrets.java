/*
 * Copyright (c) 2002, 2017, Oracle and/or its affiliates. All rights reserved.
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

package jdk.internal.misc;


import java.util.ResourceBundle;
import java.util.jar.JarFile;
import java.io.Console;
import java.io.FileDescriptor;
import java.io.FilePermission;
import java.io.ObjectInputStream;
import java.io.RandomAccessFile;
import java.security.ProtectionDomain;
import java.security.AccessController;

/** A repository of "shared secrets", which are a mechanism for
    calling implementation-private methods in another package without
    using reflection. A package-private class implements a public
    interface and provides the ability to call package-private methods
    within that package; the object implementing that interface is
    provided through a third package to which access is restricted.
    This framework avoids the primary disadvantage of using reflection
    for this purpose, namely the loss of compile-time checking. */

public class SharedSecrets {
    private static final Unsafe unsafe = Unsafe.getUnsafe();
    private static JavaUtilJarAccess javaUtilJarAccess;
//    private static JavaLangAccess javaLangAccess;
//    private static JavaLangModuleAccess javaLangModuleAccess;
    private static JavaLangInvokeAccess javaLangInvokeAccess;
    private static JavaLangRefAccess javaLangRefAccess;
    private static JavaIOAccess javaIOAccess;
    private static JavaNetInetAddressAccess javaNetInetAddressAccess;
    private static JavaNetHttpCookieAccess javaNetHttpCookieAccess;
    private static JavaNetSocketAccess javaNetSocketAccess;
    private static JavaNetUriAccess javaNetUriAccess;
    private static JavaNetURLAccess javaNetURLAccess;
    private static JavaNetURLClassLoaderAccess javaNetURLClassLoaderAccess;
    private static JavaNioAccess javaNioAccess;
    private static JavaIOFileDescriptorAccess javaIOFileDescriptorAccess;
    private static JavaIOFilePermissionAccess javaIOFilePermissionAccess;
    private static JavaSecurityProtectionDomainAccess javaSecurityProtectionDomainAccess;
    private static JavaSecurityAccess javaSecurityAccess;
    private static JavaUtilZipFileAccess javaUtilZipFileAccess;
    private static JavaUtilResourceBundleAccess javaUtilResourceBundleAccess;
    private static JavaAWTAccess javaAWTAccess;
    private static JavaAWTFontAccess javaAWTFontAccess;
    private static JavaBeansAccess javaBeansAccess;
    private static JavaObjectInputStreamAccess javaObjectInputStreamAccess;
    private static JavaIORandomAccessFileAccess javaIORandomAccessFileAccess;

    public static JavaUtilJarAccess javaUtilJarAccess() {
        if (javaUtilJarAccess == null) {
            // Ensure JarFile is initialized; we know that that class
            // provides the shared secret
            unsafe.ensureClassInitialized(JarFile.class);
        }
        return javaUtilJarAccess;
    }

    public static void setJavaUtilJarAccess(final JavaUtilJarAccess access) {
        javaUtilJarAccess = access;
    }

//    public static void setJavaLangAccess(final JavaLangAccess jla) {
//        javaLangAccess = jla;
//    }

//    public static JavaLangAccess getJavaLangAccess() {
//        return javaLangAccess;
//    }

    public static void setJavaLangInvokeAccess(final JavaLangInvokeAccess jlia) {
        javaLangInvokeAccess = jlia;
    }

    public static JavaLangInvokeAccess getJavaLangInvokeAccess() {
        if (javaLangInvokeAccess == null) {
            try {
                final Class<?> c = Class.forName("java.lang.invoke.MethodHandleImpl");
                unsafe.ensureClassInitialized(c);
            } catch (final ClassNotFoundException e) {};
        }
        return javaLangInvokeAccess;
    }

//    public static void setJavaLangModuleAccess(final JavaLangModuleAccess jlrma) {
//        javaLangModuleAccess = jlrma;
//    }

//    public static JavaLangModuleAccess getJavaLangModuleAccess() {
//        if (javaLangModuleAccess == null) {
//            unsafe.ensureClassInitialized(ModuleDescriptor.class);
//        }
//        return javaLangModuleAccess;
//    }

    public static void setJavaLangRefAccess(final JavaLangRefAccess jlra) {
        javaLangRefAccess = jlra;
    }

    public static JavaLangRefAccess getJavaLangRefAccess() {
        return javaLangRefAccess;
    }

    public static void setJavaNetUriAccess(final JavaNetUriAccess jnua) {
        javaNetUriAccess = jnua;
    }

    public static JavaNetUriAccess getJavaNetUriAccess() {
        if (javaNetUriAccess == null)
            unsafe.ensureClassInitialized(java.net.URI.class);
        return javaNetUriAccess;
    }

    public static void setJavaNetURLAccess(final JavaNetURLAccess jnua) {
        javaNetURLAccess = jnua;
    }

    public static JavaNetURLAccess getJavaNetURLAccess() {
        if (javaNetURLAccess == null)
            unsafe.ensureClassInitialized(java.net.URL.class);
        return javaNetURLAccess;
    }

    public static void setJavaNetURLClassLoaderAccess(final JavaNetURLClassLoaderAccess jnua) {
        javaNetURLClassLoaderAccess = jnua;
    }

    public static JavaNetURLClassLoaderAccess getJavaNetURLClassLoaderAccess() {
        if (javaNetURLClassLoaderAccess == null)
            unsafe.ensureClassInitialized(java.net.URLClassLoader.class);
        return javaNetURLClassLoaderAccess;
    }

    public static void setJavaNetInetAddressAccess(final JavaNetInetAddressAccess jna) {
        javaNetInetAddressAccess = jna;
    }

    public static JavaNetInetAddressAccess getJavaNetInetAddressAccess() {
        if (javaNetInetAddressAccess == null)
            unsafe.ensureClassInitialized(java.net.InetAddress.class);
        return javaNetInetAddressAccess;
    }

    public static void setJavaNetHttpCookieAccess(final JavaNetHttpCookieAccess a) {
        javaNetHttpCookieAccess = a;
    }

    public static JavaNetHttpCookieAccess getJavaNetHttpCookieAccess() {
        if (javaNetHttpCookieAccess == null)
            unsafe.ensureClassInitialized(java.net.HttpCookie.class);
        return javaNetHttpCookieAccess;
    }

    public static void setJavaNetSocketAccess(final JavaNetSocketAccess jnsa) {
        javaNetSocketAccess = jnsa;
    }

    public static JavaNetSocketAccess getJavaNetSocketAccess() {
        if (javaNetSocketAccess == null)
            unsafe.ensureClassInitialized(java.net.ServerSocket.class);
        return javaNetSocketAccess;
    }

    public static void setJavaNioAccess(final JavaNioAccess jna) {
        javaNioAccess = jna;
    }

    public static JavaNioAccess getJavaNioAccess() {
        if (javaNioAccess == null) {
            // Ensure java.nio.ByteOrder is initialized; we know that
            // this class initializes java.nio.Bits that provides the
            // shared secret.
            unsafe.ensureClassInitialized(java.nio.ByteOrder.class);
        }
        return javaNioAccess;
    }

    public static void setJavaIOAccess(final JavaIOAccess jia) {
        javaIOAccess = jia;
    }

    public static JavaIOAccess getJavaIOAccess() {
        if (javaIOAccess == null) {
            unsafe.ensureClassInitialized(Console.class);
        }
        return javaIOAccess;
    }

    public static void setJavaIOFileDescriptorAccess(final JavaIOFileDescriptorAccess jiofda) {
        javaIOFileDescriptorAccess = jiofda;
    }

    public static JavaIOFilePermissionAccess getJavaIOFilePermissionAccess() {
        if (javaIOFilePermissionAccess == null)
            unsafe.ensureClassInitialized(FilePermission.class);

        return javaIOFilePermissionAccess;
    }

    public static void setJavaIOFilePermissionAccess(final JavaIOFilePermissionAccess jiofpa) {
        javaIOFilePermissionAccess = jiofpa;
    }

    public static JavaIOFileDescriptorAccess getJavaIOFileDescriptorAccess() {
        if (javaIOFileDescriptorAccess == null)
            unsafe.ensureClassInitialized(FileDescriptor.class);

        return javaIOFileDescriptorAccess;
    }

    public static void setJavaSecurityProtectionDomainAccess
        (final JavaSecurityProtectionDomainAccess jspda) {
            javaSecurityProtectionDomainAccess = jspda;
    }

    public static JavaSecurityProtectionDomainAccess
        getJavaSecurityProtectionDomainAccess() {
            if (javaSecurityProtectionDomainAccess == null)
                unsafe.ensureClassInitialized(ProtectionDomain.class);
            return javaSecurityProtectionDomainAccess;
    }

    public static void setJavaSecurityAccess(final JavaSecurityAccess jsa) {
        javaSecurityAccess = jsa;
    }

    public static JavaSecurityAccess getJavaSecurityAccess() {
        if (javaSecurityAccess == null) {
            unsafe.ensureClassInitialized(AccessController.class);
        }
        return javaSecurityAccess;
    }

    public static JavaUtilZipFileAccess getJavaUtilZipFileAccess() {
        if (javaUtilZipFileAccess == null)
            unsafe.ensureClassInitialized(java.util.zip.ZipFile.class);
        return javaUtilZipFileAccess;
    }

    public static void setJavaUtilZipFileAccess(final JavaUtilZipFileAccess access) {
        javaUtilZipFileAccess = access;
    }

    public static void setJavaAWTAccess(final JavaAWTAccess jaa) {
        javaAWTAccess = jaa;
    }

    public static JavaAWTAccess getJavaAWTAccess() {
        // this may return null in which case calling code needs to
        // provision for.
        return javaAWTAccess;
    }

    public static void setJavaAWTFontAccess(final JavaAWTFontAccess jafa) {
        javaAWTFontAccess = jafa;
    }

    public static JavaAWTFontAccess getJavaAWTFontAccess() {
        // this may return null in which case calling code needs to
        // provision for.
        return javaAWTFontAccess;
    }

    public static JavaBeansAccess getJavaBeansAccess() {
        return javaBeansAccess;
    }

    public static void setJavaBeansAccess(final JavaBeansAccess access) {
        javaBeansAccess = access;
    }

    public static JavaUtilResourceBundleAccess getJavaUtilResourceBundleAccess() {
        if (javaUtilResourceBundleAccess == null)
            unsafe.ensureClassInitialized(ResourceBundle.class);
        return javaUtilResourceBundleAccess;
    }

    public static void setJavaUtilResourceBundleAccess(final JavaUtilResourceBundleAccess access) {
        javaUtilResourceBundleAccess = access;
    }

    public static JavaObjectInputStreamAccess getJavaObjectInputStreamAccess() {
        if (javaObjectInputStreamAccess == null) {
            unsafe.ensureClassInitialized(ObjectInputStream.class);
        }
        return javaObjectInputStreamAccess;
    }

    public static void setJavaObjectInputStreamAccess(final JavaObjectInputStreamAccess access) {
        javaObjectInputStreamAccess = access;
    }

    public static void setJavaIORandomAccessFileAccess(final JavaIORandomAccessFileAccess jirafa) {
        javaIORandomAccessFileAccess = jirafa;
    }

    public static JavaIORandomAccessFileAccess getJavaIORandomAccessFileAccess() {
        if (javaIORandomAccessFileAccess == null) {
            unsafe.ensureClassInitialized(RandomAccessFile.class);
        }
        return javaIORandomAccessFileAccess;
    }
}
