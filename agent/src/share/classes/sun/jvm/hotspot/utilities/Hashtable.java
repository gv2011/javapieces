/*
 * Copyright 2003 Sun Microsystems, Inc.  All Rights Reserved.
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

package sun.jvm.hotspot.utilities;

import java.util.*;
import sun.jvm.hotspot.debugger.*;
import sun.jvm.hotspot.types.*;
import sun.jvm.hotspot.runtime.*;

public class Hashtable extends BasicHashtable {
  static {
    VM.registerVMInitializedObserver(new Observer() {
        public void update(Observable o, Object data) {
          initialize(VM.getVM().getTypeDataBase());
        }
      });
  }

  private static synchronized void initialize(TypeDataBase db) {
    // just to confirm that type exists
    Type type = db.lookupType("Hashtable");
  }

  // derived class may return Class<? extends HashtableEntry>
  protected Class getHashtableEntryClass() {
    return HashtableEntry.class;
  }

  public int hashToIndex(long fullHash) {
    return (int) (fullHash % tableSize());
  }

  public Hashtable(Address addr) {
    super(addr);
  }

  // VM's Hashtable::hash_symbol
  protected static long hashSymbol(byte[] buf) {
    long h = 0;
    int s = 0;
    int len = buf.length;
    while (len-- > 0) {
      h = 31*h + (0xFFL & buf[s]);
      s++;
    }
    return h & 0xFFFFFFFFL;
  }
}
