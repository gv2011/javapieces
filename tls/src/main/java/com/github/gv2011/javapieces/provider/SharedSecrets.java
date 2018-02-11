package com.github.gv2011.javapieces.provider;

import java.nio.charset.CharsetEncoder;

public class SharedSecrets {

  public static JavaSecurityProtectionDomainAccess getJavaSecurityProtectionDomainAccess() {
    return new JavaSecurityProtectionDomainAccess();
  }

  public static CharsetEncoder getJavaIOAccess() {
    // TODO Auto-generated method stub
    throw notYetImplementedException();
  }

  private static RuntimeException notYetImplementedException() {
    // TODO Auto-generated method stub
    throw notYetImplementedException();
  }

  public static JavaNetAccess getJavaNetAccess() {
    // TODO Auto-generated method stub
    throw notYetImplementedException();
  }

}
