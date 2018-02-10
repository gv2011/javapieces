/*
 * Copyright (c) 1997, 2001, Oracle and/or its affiliates. All rights reserved.
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


package com.github.gv2011.javapieces.tls;

/*-
 * #%L
 * javapieces-tls
 * %%
 * Copyright (C) 2018 Vinz (https://github.com/gv2011)
 * %%
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * #L%
 */
import java.util.EventListener;



/**
 * This interface is implemented by objects which want to know when
 * they are being bound or unbound from a SSLSession.  When either event
 * occurs via {@link SSLSession#putValue(String, Object)}
 * or {@link SSLSession#removeValue(String)}, the event is communicated
 * through a SSLSessionBindingEvent identifying the session.
 *
 * @see SSLSession
 * @see SSLSessionBindingEvent
 *
 * @since 1.4
 * @author Nathan Abramson
 * @author David Brownell
 */
public
interface SSLSessionBindingListener
extends EventListener
{
    /**
     * This is called to notify the listener that it is being bound into
     * an SSLSession.
     *
     * @param event the event identifying the SSLSession into
     *          which the listener is being bound.
     */
    public void valueBound(SSLSessionBindingEvent event);

    /**
     * This is called to notify the listener that it is being unbound
     * from a SSLSession.
     *
     * @param event the event identifying the SSLSession from
     *          which the listener is being unbound.
     */
    public void valueUnbound(SSLSessionBindingEvent event);
}
