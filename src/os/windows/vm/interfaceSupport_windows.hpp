#ifdef USE_PRAGMA_IDENT_HDR
#pragma ident "@(#)interfaceSupport_windows.hpp	1.7 07/05/05 17:04:44 JVM"
#endif
/*
 * Copyright 2005 Sun Microsystems, Inc.  All Rights Reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
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
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *  
 */

// Contains inlined functions for class InterfaceSupport

static inline void serialize_memory(JavaThread *thread) {
  // due to chained nature of SEH handlers we have to be sure 
  // that our handler is always last handler before an attempt to write
  // into serialization page - it can fault if we access this page
  // right in the middle of protect/unprotect sequence by remote
  // membar logic.
  // __try/__except are very lightweight operations (only several 
  // instructions not affecting control flow directly on x86)
  // so we can use it here, on very time critical path
  __try {
    os::write_memory_serialize_page(thread);
  } __except (os::win32::
              serialize_fault_filter((_EXCEPTION_POINTERS*)_exception_info())) 
    {}
}
