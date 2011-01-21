/*
 * Copyright (c) 2011, Axel Nennker - http://axel.nennker.de/
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the names xmldap, xmldap.org, xmldap.com nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.xmldap.json;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import junit.framework.TestCase;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.json.JSONException;
import org.json.JSONObject;
import org.xmldap.util.Base64;

public class WebTokenTest extends TestCase {
  JSONObject joeO = null;

  String joeStr = "{\"iss\":\"joe\",\r\n" +
      " \"exp\":1300819380,\r\n" +
      " \"http://example.com/is_root\":true}";
  
  String hs256 = "{\"typ\":\"JWT\",\r\n"+
                 " \"alg\":\"HS256\"}";
  String hs384 = "{\"typ\":\"JWT\",\r\n"+
                 " \"alg\":\"HS384\"}";
  String hs512 = "{\"typ\":\"JWT\",\r\n"+
                 " \"alg\":\"HS512\"}";
  byte[] hsKey = {3, (byte)35, (byte)53, (byte)75, (byte)43, (byte)15, (byte)165, (byte)188, (byte)131, (byte)126, (byte)6, (byte)101, (byte)119, (byte)123, (byte)166, (byte)143, (byte)90, (byte)179, (byte)40, (byte)230, (byte)240, (byte)84, (byte)201, (byte)40, (byte)169, (byte)15, (byte)132, (byte)178, (byte)210, (byte)80, (byte)46, (byte)191, (byte)211, (byte)251, (byte)90, (byte)146, (byte)210, (byte)6, (byte)71, (byte)239, (byte)150, (byte)138, (byte)180, (byte)195, (byte)119, (byte)98, (byte)61, (byte)34, (byte)61, (byte)46, (byte)33, (byte)114, (byte)5, (byte)46, (byte)79, (byte)8, (byte)192, (byte)205, (byte)154, (byte)245, (byte)103, (byte)208, (byte)128, (byte)163};
  
  String es256 = "{\"alg\":\"ES256\"}";
  String es384 = "{\"alg\":\"ES384\"}";
  String es512 = "{\"alg\":\"ES512\"}";

  String rs256 = "{\"alg\":\"RS256\"}";
  String rs384 = "{\"alg\":\"RS384\"}";
  String rs512 = "{\"alg\":\"RS512\"}";

  String re256;
  String re256b64;
  
  RSAPublicKey rsaPublicKey;
  RSAPrivateKey rsaPrivKey;
  
  public void setUp() {
    try {
      super.setUp();
      
      final byte[] n = {(byte)161, (byte)248, (byte)22, (byte)10, (byte)226, (byte)227, (byte)201, (byte)180, (byte)101, (byte)206, (byte)141, (byte)45, (byte)101, (byte)98, (byte)99, (byte)54, (byte)43, (byte)146, (byte)125, (byte)190, (byte)41, (byte)225, (byte)240, (byte)36, (byte)119, (byte)252, (byte)22, (byte)37, (byte)204, (byte)144, (byte)161, (byte)54, (byte)227, (byte)139, (byte)217, (byte)52, (byte)151, (byte)197, (byte)182, (byte)234, (byte)99, (byte)221, (byte)119, (byte)17, (byte)230, (byte)124, (byte)116, (byte)41, (byte)249, (byte)86, (byte)176, (byte)251, (byte)138, (byte)143, (byte)8, (byte)154, (byte)220, (byte)75, (byte)105, (byte)137, (byte)60, (byte)193, (byte)51, (byte)63, (byte)83, (byte)237, (byte)208, (byte)25, (byte)184, (byte)119, (byte)132, (byte)37, (byte)47, (byte)236, (byte)145, (byte)79, (byte)228, (byte)133, (byte)119, (byte)105, (byte)89, (byte)75, (byte)234, (byte)66, (byte)128, (byte)211, (byte)44, (byte)15, (byte)85, (byte)191, (byte)98, (byte)148, (byte)79, (byte)19, (byte)3, (byte)150, (byte)188, (byte)110, (byte)155, (byte)223, (byte)110, (byte)189, (byte)210, (byte)189, (byte)163, (byte)103, (byte)142, (byte)236, (byte)160, (byte)198, (byte)104, (byte)247, (byte)1, (byte)179, (byte)141, (byte)191, (byte)251, (byte)56, (byte)200, (byte)52, (byte)44, (byte)226, (byte)254, (byte)109, (byte)39, (byte)250, (byte)222, (byte)74, (byte)90, (byte)72, (byte)116, (byte)151, (byte)157, (byte)212, (byte)185, (byte)207, (byte)154, (byte)222, (byte)196, (byte)199, (byte)91, (byte)5, (byte)133, (byte)44, (byte)44, (byte)15, (byte)94, (byte)248, (byte)165, (byte)193, (byte)117, (byte)3, (byte)146, (byte)249, (byte)68, (byte)232, (byte)237, (byte)100, (byte)193, (byte)16, (byte)198, (byte)182, (byte)71, (byte)96, (byte)154, (byte)164, (byte)120, (byte)58, (byte)235, (byte)156, (byte)108, (byte)154, (byte)215, (byte)85, (byte)49, (byte)48, (byte)80, (byte)99, (byte)139, (byte)131, (byte)102, (byte)92, (byte)111, (byte)111, (byte)122, (byte)130, (byte)163, (byte)150, (byte)112, (byte)42, (byte)31, (byte)100, (byte)27, (byte)130, (byte)211, (byte)235, (byte)242, (byte)57, (byte)34, (byte)25, (byte)73, (byte)31, (byte)182, (byte)134, (byte)135, (byte)44, (byte)87, (byte)22, (byte)245, (byte)10, (byte)248, (byte)53, (byte)141, (byte)154, (byte)139, (byte)157, (byte)23, (byte)195, (byte)64, (byte)114, (byte)143, (byte)127, (byte)135, (byte)216, (byte)154, (byte)24, (byte)216, (byte)252, (byte)171, (byte)103, (byte)173, (byte)132, (byte)89, (byte)12, (byte)46, (byte)207, (byte)117, (byte)147, (byte)57, (byte)54, (byte)60, (byte)7, (byte)3, (byte)77, (byte)111, (byte)96, (byte)111, (byte)158, (byte)33, (byte)224, (byte)84, (byte)86, (byte)202, (byte)229, (byte)233, (byte)161};
      final byte[] e = {1, 0, 1};
      final byte[] d = {18, (byte)174, (byte)113, (byte)164, (byte)105, (byte)205, (byte)10, (byte)43, (byte)195, (byte)126, (byte)82, (byte)108, (byte)69, (byte)0, (byte)87, (byte)31, (byte)29, (byte)97, (byte)117, (byte)29, (byte)100, (byte)233, (byte)73, (byte)112, (byte)123, (byte)98, (byte)89, (byte)15, (byte)157, (byte)11, (byte)165, (byte)124, (byte)150, (byte)60, (byte)64, (byte)30, (byte)63, (byte)207, (byte)47, (byte)44, (byte)211, (byte)189, (byte)236, (byte)136, (byte)229, (byte)3, (byte)191, (byte)198, (byte)67, (byte)155, (byte)11, (byte)40, (byte)200, (byte)47, (byte)125, (byte)55, (byte)151, (byte)103, (byte)31, (byte)82, (byte)19, (byte)238, (byte)216, (byte)193, (byte)90, (byte)37, (byte)216, (byte)213, (byte)206, (byte)160, (byte)2, (byte)94, (byte)227, (byte)171, (byte)46, (byte)139, (byte)127, (byte)121, (byte)33, (byte)111, (byte)198, (byte)59, (byte)234, (byte)86, (byte)39, (byte)83, (byte)180, (byte)6, (byte)68, (byte)198, (byte)161, (byte)81, (byte)39, (byte)217, (byte)178, (byte)149, (byte)69, (byte)64, (byte)160, (byte)187, (byte)225, (byte)163, (byte)5, (byte)86, (byte)152, (byte)45, (byte)78, (byte)159, (byte)222, (byte)95, (byte)100, (byte)37, (byte)241, (byte)77, (byte)75, (byte)113, (byte)52, (byte)65, (byte)181, (byte)93, (byte)199, (byte)59, (byte)155, (byte)74, (byte)237, (byte)204, (byte)146, (byte)172, (byte)227, (byte)146, (byte)126, (byte)55, (byte)245, (byte)125, (byte)12, (byte)253, (byte)94, (byte)117, (byte)129, (byte)250, (byte)81, (byte)44, (byte)143, (byte)73, (byte)97, (byte)169, (byte)235, (byte)11, (byte)128, (byte)248, (byte)168, (byte)7, (byte)70, (byte)114, (byte)138, (byte)85, (byte)255, (byte)70, (byte)71, (byte)31, (byte)52, (byte)37, (byte)6, (byte)59, (byte)157, (byte)83, (byte)100, (byte)47, (byte)94, (byte)222, (byte)30, (byte)132, (byte)214, (byte)19, (byte)8, (byte)26, (byte)250, (byte)92, (byte)34, (byte)208, (byte)81, (byte)40, (byte)91, (byte)214, (byte)59, (byte)148, (byte)59, (byte)86, (byte)93, (byte)137, (byte)138, (byte)5, (byte)104, (byte)84, (byte)19, (byte)229, (byte)60, (byte)60, (byte)108, (byte)101, (byte)37, (byte)255, (byte)31, (byte)227, (byte)78, (byte)61, (byte)220, (byte)112, (byte)240, (byte)213, (byte)100, (byte)80, (byte)253, (byte)164, (byte)139, (byte)161, (byte)46, (byte)16, (byte)78, (byte)157, (byte)235, (byte)159, (byte)184, (byte)24, (byte)129, (byte)225, (byte)196, (byte)189, (byte)242, (byte)93, (byte)146, (byte)71, (byte)244, (byte)80, (byte)200, (byte)101, (byte)146, (byte)121, (byte)104, (byte)231, (byte)115, (byte)52, (byte)244, (byte)65, (byte)79, (byte)117, (byte)167, (byte)80, (byte)225, (byte)57, (byte)84, (byte)110, (byte)58, (byte)138, (byte)115, (byte)157};
      
      BigInteger N = new BigInteger(1, n);
      BigInteger E = new BigInteger(1, e);
      BigInteger D = new BigInteger(1, d);
      
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(N, E);
      RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(N, D);
      rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);
      rsaPrivKey = (RSAPrivateKey) keyFactory.generatePrivate(privKeySpec);
      
      Digest digest = new SHA256Digest();
      byte[] bytes = rsaPublicKey.getEncoded();
      digest.update(bytes, 0, bytes.length);
      byte[] out = new byte[digest.getDigestSize()];
      /*int result =*/ digest.doFinal(out, 0);
      String thumbprint = Base64.encodeBytes(out, 
          org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);

      re256 = "{\"alg\":\"RE256\",\r\n"+
      " \"thu\":\"" + thumbprint + "\"}";
      re256b64 = Base64.encodeBytes(re256.getBytes("utf-8"), 
          org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);

    } catch (Exception e) {
      assertTrue(false);
    }
  }

  public void testJoeEncoding() throws UnsupportedEncodingException {
    byte[] bytes = joeStr.getBytes("utf-8");
    String base64urlStr = Base64.encodeBytes(bytes, 
        org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
    String expected = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
    assertEquals(expected, base64urlStr);
  }

  public void testHS256Encoding() throws UnsupportedEncodingException {
    byte[] bytes = hs256.getBytes("utf-8");
    String base64urlStr = Base64.encodeBytes(bytes, 
        org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
    String expected = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";
    assertEquals(expected, base64urlStr);
  }

  public void testES256Encoding() throws UnsupportedEncodingException {
    byte[] bytes = es256.getBytes("utf-8");
    String base64urlStr = Base64.encodeBytes(bytes, 
        org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
    String expected = "eyJhbGciOiJFUzI1NiJ9";
    assertEquals(expected, base64urlStr);
  }

//  public void testProviders() {
//    Security.addProvider(new BouncyCastleProvider());
//    Provider[] providers = java.security.Security.getProviders();
//    for (int i=0; i<providers.length; i++) {
//      Provider p = providers[i];
//      System.out.println(p.getName());
//    }
//  }
  
  public void testEDSAsignature_Draft01() 
  throws Exception {
    String signature = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
    byte[] x = {127, (byte)205, (byte)206, (byte)39, (byte)112, (byte)246, (byte)196, (byte)93, (byte)65, (byte)131, (byte)203, (byte)238, (byte)111, (byte)219, (byte)75, (byte)123, (byte)88, (byte)7, (byte)51, (byte)53, (byte)123, (byte)233, (byte)239, (byte)19, (byte)186, (byte)207, (byte)110, (byte)60, (byte)123, (byte)209, (byte)84, (byte)69};
    byte[] y = {(byte)199, (byte)241, (byte)68, (byte)205, (byte)27, (byte)189, (byte)155, (byte)126, (byte)135, (byte)44, (byte)223, (byte)237, (byte)185, (byte)238, (byte)185, (byte)244, (byte)179, (byte)105, (byte)93, (byte)110, (byte)169, (byte)11, (byte)36, (byte)173, (byte)138, (byte)70, (byte)35, (byte)40, (byte)133, (byte)136, (byte)229, (byte)173};

    assertTrue(WebToken.verify(signature, x, y));
  }
  
  public void testEDSAsignature() 
  throws Exception {
//    byte[] x = {48, (byte)160, 66, 76, (byte)210, 28, 41, 68, (byte)131, (byte)138, 45, 117, (byte)201, 43, 55, (byte)231, 110, (byte)162, 13, (byte)159, 0, (byte)137, 58, 59, 78, (byte)238, (byte)138, 60, 10, (byte)175, (byte)236, 62};
//    byte[] y = {(byte)224, 75, 101, (byte)233, 36, 86, (byte)217, (byte)136, (byte)139, 82, (byte)179, 121, (byte)189, (byte)251, (byte)213, 30, (byte)232, 105, (byte)239, 31, 15, (byte)198, 91, 102, 89, 105, 91, 108, (byte)206, 8, 23, 35};
    byte[] d = {(byte)243, (byte)189, 12, 7, (byte)168, 31, (byte)185, 50, 120, 30, (byte)213, 39, 82, (byte)246, 12, (byte)200, (byte)154, 107, (byte)229, (byte)229, 25, 52, (byte)254, 1, (byte)147, (byte)141, (byte)219, 85, (byte)216, (byte)247, 120, 1};
    
//    "secp256r1 [NIST P-256, X9.62 prime256v1]", "1.2.840.10045.3.1.7"
    WebToken wt = new WebToken(joeStr, es256);
    String signed = wt.serialize(new BigInteger(1,d));
    String[] split = signed.split("\\.");
    assertEquals(3, split.length);
    assertEquals("eyJhbGciOiJFUzI1NiJ9", split[0]);
    assertEquals("eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ", split[1]);
    byte[] signatureBytes = Base64.decodeUrl(split[2]);
    assertEquals(64, signatureBytes.length);
    byte[] x = {48, (byte)160, 66, 76, (byte)210, 28, 41, 68, (byte)131, (byte)138, 45, 117, (byte)201, 43, 55, (byte)231, 110, (byte)162, 13, (byte)159, 0, (byte)137, 58, 59, 78, (byte)238, (byte)138, 60, 10, (byte)175, (byte)236, 62};
    byte[] y = {(byte)224, 75, 101, (byte)233, 36, 86, (byte)217, (byte)136, (byte)139, 82, (byte)179, 121, (byte)189, (byte)251, (byte)213, 30, (byte)232, 105, (byte)239, 31, 15, (byte)198, 91, 102, 89, 105, 91, 108, (byte)206, 8, 23, 35};
    assertTrue(WebToken.verify(signed, x, y));

  }
  
  private void testHMACSHA(
      String jwtAlgorithm, String jwtHeaderSegment, String jwtCryptoSegment) 
  throws InvalidKeyException, NoSuchAlgorithmException, IllegalStateException, UnsupportedEncodingException, JSONException {
    WebToken jwt = new WebToken(joeStr, jwtAlgorithm);
    String signed = jwt.serialize(hsKey);
    String[] split = signed.split("\\.");
    assertEquals(3, split.length);
    assertEquals(jwtHeaderSegment, split[0]);
    assertEquals("eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ", split[1]);
    assertEquals(jwtCryptoSegment, split[2]);
    String expected = split[0] + "." + split[1] + "." + split[2];
    assertEquals(expected, signed);
  }
  
  public void testHS256() throws InvalidKeyException, NoSuchAlgorithmException, IllegalStateException, UnsupportedEncodingException, JSONException {
    testHMACSHA(hs256, "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); 
  }

  public void testHS384() throws InvalidKeyException, NoSuchAlgorithmException, IllegalStateException, UnsupportedEncodingException, JSONException {
    testHMACSHA(hs384, "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzM4NCJ9", 
        "TUfcA4Xjq_veopvw1fiFG99UswFSMvxYisxxBb0kHQ7w8He3OkvmELPo0uy3RuR0"); 
  }
  
  public void testHS512() throws InvalidKeyException, NoSuchAlgorithmException, IllegalStateException, UnsupportedEncodingException, JSONException {
    testHMACSHA(hs512, "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzUxMiJ9", 
        "iXxB-yPnHRvriuSAfTrwz-gr5WYC6tg7gIq9JndRI9Uqn4D6twBgsJuQsQks6WqAC6OB23Lvdht79p_lA6jE8g"); 
  }
  
  private void testRSASHA(
      String jwtAlgorithm, String jwtHeaderSegment, String jwtCryptoSegment) 
  throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException, JSONException, IOException {
    WebToken jwt = new WebToken(joeStr, jwtAlgorithm);

    String signed = jwt.serialize(rsaPrivKey);
    String[] split = signed.split("\\.");
    
    assertEquals(3, split.length);
    assertEquals(jwtHeaderSegment, split[0]);
    String jwtPayloadSegment = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
    assertEquals(jwtPayloadSegment, split[1]);
    assertEquals(jwtCryptoSegment, split[2]);
    
    String expected = jwtHeaderSegment + "." + jwtPayloadSegment + "." + jwtCryptoSegment;
    assertEquals(expected, signed);

  }

  public void testRS256() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException, JSONException, IOException {
    String jwtHeaderSegment = "eyJhbGciOiJSUzI1NiJ9";
    String jwtCryptoSegment = "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";
    testRSASHA(rs256, jwtHeaderSegment, jwtCryptoSegment);
  }
  
  public void testRS384() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException, JSONException, IOException {
    String jwtHeaderSegment = "eyJhbGciOiJSUzM4NCJ9";
    String jwtCryptoSegment = "UqgNjrJOGhk4wfoSG6Uvrt9GcKu-TgPwInExALrMBadg1pol1uTw7mZADTddAWsC6ZzdFiTFUmIi7DuD38ftLAZoW4qezdAO7RYf1yZDsbT20bt8DJJN1I4VovL2PLg80B6x6ug-kaW8k5LaM5ce0dk1zgWhjafKC3Mb4UNLL8f9fqVMkHpdWYRjF6QjTz12Ap-gq-tPyUoWSdvzCIYOcZ9-08SQQdUTTgsNF1Qwu3TqeWPqzNJwmWHiHMmaV8I4ktMFEX-AiEBa55KsfYTx0jSbTHP-odqmnLQJ4n-oQJ2RSXy0HQP6BkdiwDHdoMUk4z_wAeOsfDTs_mLxTgOInQ";
    testRSASHA(rs384, jwtHeaderSegment, jwtCryptoSegment);
  }
  
  public void testRE256() throws Exception {
    String jwtHeaderSegment = re256b64;
    String payload = "some string with German umlauts δόφί";
    
    System.out.println("jwtHeaderSegment: " + re256);
    System.out.println("jwtHeaderSegment base64: " + re256b64);
    
    WebToken jwt = new WebToken(payload, re256);
    String encrypted = jwt.encrypt(rsaPublicKey);
    
    String[] split = encrypted.split("\\.");
    
    assertEquals(3, split.length);
    assertEquals(jwtHeaderSegment, split[0]);

    System.out.println("jwtSymmetricKeySegment base64: " + split[1]);
    System.out.println("jwtPayloadSegment base64: " + split[2]);

    String cleartext = WebToken.decrypt(encrypted, rsaPrivKey);
    assertEquals(payload, cleartext);
  }

}
