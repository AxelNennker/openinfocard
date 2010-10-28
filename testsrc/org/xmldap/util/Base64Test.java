package org.xmldap.util;

import org.xmldap.util.Base64;

import junit.framework.TestCase;

public class Base64Test extends TestCase {
  byte[] mJWTbytes = {0x3, (byte)236, (byte)255, (byte)224, (byte)193};

  public void setUp() throws Exception {
    super.setUp();
  }

  public void testUrlencode() throws Exception {
    String enc = Base64.encodeBytes(mJWTbytes, org.xmldap.util.Base64.URL);
    assertEquals("A-z_4ME", enc);
  }
  public void testUrldecode() throws Exception {
    byte[] decoded = Base64.decodeUrl("A-z_4ME");
    assertEquals(mJWTbytes.length, decoded.length);
    assertEquals(mJWTbytes[0], decoded[0]);
    assertEquals(mJWTbytes[1], decoded[1]);
    assertEquals(mJWTbytes[2], decoded[2]);
    assertEquals(mJWTbytes[3], decoded[3]);
  }
}
