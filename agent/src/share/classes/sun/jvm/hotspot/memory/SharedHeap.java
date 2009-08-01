/*
 * Copyright 2002-2003 Sun Microsystems, Inc.  All Rights Reserved.
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

package sun.jvm.hotspot.memory;

import java.io.*;
import java.util.*;

import sun.jvm.hotspot.debugger.*;
import sun.jvm.hotspot.gc_interface.*;
import sun.jvm.hotspot.runtime.*;
import sun.jvm.hotspot.types.*;

public abstract class SharedHeap extends CollectedHeap {
  private static AddressField permGenField;
  private static VirtualConstructor ctor;

  static {
    VM.registerVMInitializedObserver(new Observer() {
        public void update(Observable o, Object data) {
          initialize(VM.getVM().getTypeDataBase());
        }
      });
  }

  private static synchronized void initialize(TypeDataBase db) {
    Type type = db.lookupType("SharedHeap");
    permGenField        = type.getAddressField("_perm_gen");
    ctor = new VirtualConstructor(db);
    ctor.addMapping("CompactingPermGen", CompactingPermGen.class);
    ctor.addMapping("CMSPermGen", CMSPermGen.class);

  }

  public SharedHeap(Address addr) {
    super(addr);
  }

  /** These functions return the "permanent" generation, in which
      reflective objects are allocated and stored.  Two versions, the
      second of which returns the view of the perm gen as a
      generation. (FIXME: this distinction is strange and seems
      unnecessary, and should be cleaned up.) */
  public PermGen perm() {
    return (PermGen) ctor.instantiateWrapperFor(permGenField.getValue(addr));
  }

  public CollectedHeapName kind() {
    return CollectedHeapName.SHARED_HEAP; 
  }

  public Generation permGen() {
    return perm().asGen();
  }
}
