/*
 * Copyright 2002 Sun Microsystems, Inc.  All Rights Reserved.
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

package sun.jvm.hotspot.asm.sparc;

import sun.jvm.hotspot.asm.*;

public class SPARCBranchInstruction extends SPARCInstruction
    implements BranchInstruction {
    final protected PCRelativeAddress addr;
    final protected int conditionCode;
    final protected boolean isAnnuled;

    public SPARCBranchInstruction(String name, PCRelativeAddress addr, boolean isAnnuled, int conditionCode) {
        super(name);
        this.addr = addr;
        this.conditionCode = conditionCode;
        this.isAnnuled = isAnnuled;
    }

    public String asString(long currentPc, SymbolFinder symFinder) {
        long address = addr.getDisplacement() + currentPc;
        StringBuffer buf = new StringBuffer();
        buf.append(getName());
        buf.append(spaces);
        buf.append(symFinder.getSymbolFor(address));
        return buf.toString();
    }

    public Address getBranchDestination() {
        return addr;
    }

    public int getConditionCode() {
        return conditionCode;
    }

    public boolean isAnnuledBranch() {
        return isAnnuled;
    }

    public boolean isBranch() {
        return true;
    }

    public boolean isConditional() {
        return conditionCode != CONDITION_BN && conditionCode != CONDITION_BA;
    }
}
