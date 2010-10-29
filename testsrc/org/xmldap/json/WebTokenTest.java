package org.xmldap.json;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.SignatureException;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;

import junit.framework.TestCase;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.json.JSONException;
import org.json.JSONObject;
import org.xmldap.util.Base64;

import sun.security.ec.NamedCurve;

public class WebTokenTest extends TestCase {
  JSONObject joeO = null;

  String joeStr = "{\"iss\":\"joe\",\r\n" +
      " \"exp\":1300819380,\r\n" +
      " \"http://example.com/is_root\":true}";
  
  String hs256 = "{\"typ\":\"JWT\",\r\n"+
                 " \"alg\":\"HS256\"}";
  
  String es256 = "{\"alg\":\"ES256\"}";
  
  public void setUp() {
    try {
      super.setUp();
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
  
  public void testEDSAsignature() 
  throws Exception {
//    byte[] x = {48, (byte)160, 66, 76, (byte)210, 28, 41, 68, (byte)131, (byte)138, 45, 117, (byte)201, 43, 55, (byte)231, 110, (byte)162, 13, (byte)159, 0, (byte)137, 58, 59, 78, (byte)238, (byte)138, 60, 10, (byte)175, (byte)236, 62};
//    byte[] y = {(byte)224, 75, 101, (byte)233, 36, 86, (byte)217, (byte)136, (byte)139, 82, (byte)179, 121, (byte)189, (byte)251, (byte)213, 30, (byte)232, 105, (byte)239, 31, 15, (byte)198, 91, 102, 89, 105, 91, 108, (byte)206, 8, 23, 35};
    byte[] d = {(byte)243, (byte)189, 12, 7, (byte)168, 31, (byte)185, 50, 120, 30, (byte)213, 39, 82, (byte)246, 12, (byte)200, (byte)154, 107, (byte)229, (byte)229, 25, 52, (byte)254, 1, (byte)147, (byte)141, (byte)219, 85, (byte)216, (byte)247, 120, 1};
    
//    "secp256r1 [NIST P-256, X9.62 prime256v1]", "1.2.840.10045.3.1.7"
    DERObjectIdentifier oid = SECObjectIdentifiers.secp256r1;
    X9ECParameters x9ECParameters = SECNamedCurves.getByOID(oid);
    ECDomainParameters ecParameterSpec = new ECDomainParameters(
        x9ECParameters.getCurve(), 
        x9ECParameters.getG(), 
        x9ECParameters.getN(), 
        x9ECParameters.getH(), 
        x9ECParameters.getSeed());
    assertNotNull(ecParameterSpec);
    ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(
        new BigInteger(1,d), ecParameterSpec);
    WebToken wt = new WebToken(joeStr, es256);
    String signed = wt.serialize(ecPrivateKeyParameters);
    String[] split = signed.split("\\.");
    assertEquals(3, split.length);
    assertEquals("eyJhbGciOiJFUzI1NiJ9", split[0]);
    assertEquals("eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ", split[1]);
    byte[] signatureBytes = Base64.decodeUrl(split[2]);
    assertEquals(64, signatureBytes.length);
    byte[] rBytes = new byte[32];
    System.arraycopy(signatureBytes, 0, rBytes, 0, 32);
    byte[] sBytes = new byte[32];
    System.arraycopy(signatureBytes, 32, sBytes, 0, 32);
    
    BigInteger r = new BigInteger(1, rBytes);
    BigInteger s = new BigInteger(1, sBytes);
    
    {
      ECDSASigner verifier = new ECDSASigner();
      byte[] x = {48, (byte)160, 66, 76, (byte)210, 28, 41, 68, (byte)131, (byte)138, 45, 117, (byte)201, 43, 55, (byte)231, 110, (byte)162, 13, (byte)159, 0, (byte)137, 58, 59, 78, (byte)238, (byte)138, 60, 10, (byte)175, (byte)236, 62};
      byte[] y = {(byte)224, 75, 101, (byte)233, 36, 86, (byte)217, (byte)136, (byte)139, 82, (byte)179, 121, (byte)189, (byte)251, (byte)213, 30, (byte)232, 105, (byte)239, 31, 15, (byte)198, 91, 102, 89, 105, 91, 108, (byte)206, 8, 23, 35};
      BigInteger xB = new BigInteger(1, x);
      BigInteger yB = new BigInteger(1, y);
      ECCurve curve = ecPrivateKeyParameters.getParameters().getCurve();
      ECPoint qB = curve.createPoint(xB, yB, false);
      ECPoint q = new ECPoint.Fp(curve, qB.getX(), qB.getY());
      ECDomainParameters ecDomainParameters = new ECDomainParameters(
          curve, 
          ecPrivateKeyParameters.getParameters().getG(), 
          ecPrivateKeyParameters.getParameters().getN(), 
          ecPrivateKeyParameters.getParameters().getH(),
          ecPrivateKeyParameters.getParameters().getSeed());
      ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(
          q, ecDomainParameters);
      verifier.init(false, ecPublicKeyParameters);
      boolean verified = verifier.verifySignature(joeStr.getBytes("utf-8"), r, s);
      assertTrue(verified);
      System.out.println("Verfied: " + verified);
    }

  }
  
  public void test1() throws InvalidKeyException, NoSuchAlgorithmException, IllegalStateException, UnsupportedEncodingException, JSONException {
    String algorithm = null;
    WebToken jwt = new WebToken(joeStr, hs256);
    byte[] key = {83, (byte)159, 117, 12, (byte)235, (byte)169, (byte)168, (byte)200, (byte)131, (byte)152, (byte)227, (byte)246, (byte)214, (byte)212, (byte)188, 74, 71, 83, (byte)244, (byte)166, 90, 24, (byte)239, (byte)251, 32, 124, 6, (byte)201, (byte)194, 104, (byte)241, 62, (byte)174, (byte)246, 65, 111, 49, 52, (byte)210, 118, (byte)212, 124, 34, 88, (byte)167, 112, 84, 88, 83, 65, (byte)155, 18, (byte)234, (byte)250, (byte)224, 101, (byte)147, (byte)221, 23, 104, (byte)219, (byte)170, (byte)146, (byte)215};
    String signed = jwt.serialize(key);
    String[] split = signed.split("\\.");
    assertEquals(3, split.length);
    assertEquals("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9", split[0]);
    assertEquals("eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ", split[1]);
    assertEquals("35usWj9X8HwGS-CDcx1JP2NmqcrLwZ4EKp8sNThf3cY", split[2]);
    String expected = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.35usWj9X8HwGS-CDcx1JP2NmqcrLwZ4EKp8sNThf3cY";
    assertEquals(expected, signed);
  }
}
