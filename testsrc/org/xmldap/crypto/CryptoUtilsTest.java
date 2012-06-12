/*
 * Copyright (c) 2012, Axel Nennker - http://axel.nennker.de/
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
package org.xmldap.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

import junit.framework.TestCase;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.params.KDFParameters;
import org.xmldap.exceptions.CryptoException;
import org.xmldap.util.Base64;
import org.xmldap.util.XmldapCertsAndKeys;

public class CryptoUtilsTest extends TestCase {

  protected void setUp() throws Exception {
    super.setUp();
  }

  public void testByteDigest() {
    byte[] data = "test".getBytes();
    try {
      byte[] digest = CryptoUtils.byteDigest(data, "SHA");
      String digestB64 = Base64.encodeBytesNoBreaks(digest);
      assertEquals("qUqP5cyxm6YcTAhz05Hph5gvu9M=", digestB64);
    } catch (CryptoException e) {
      assertEquals("", e.getMessage());
    }
    
    data = new byte[1024];
    for (int i=0; i<data.length; i++) {
      data[i] = (byte)(i & 0xFF);
    }
    try {
      byte[] digest = CryptoUtils.byteDigest(data, "SHA");
      String digestB64 = Base64.encodeBytesNoBreaks(digest);
      assertEquals("WwBmnEgNXP+9+ovbqZVhFg8tG3c=", digestB64);
    } catch (CryptoException e) {
      assertEquals("", e.getMessage());
    }
  }

  public void testDigest() {
    byte[] data = "test".getBytes();
    try {
      String b64 = CryptoUtils.digest(data, "SHA");
      assertEquals("qUqP5cyxm6YcTAhz05Hph5gvu9M=", b64);
    } catch (CryptoException e) {
      assertEquals("", e.getMessage());
    }
    data = new byte[1024];
    for (int i=0; i<data.length; i++) {
      data[i] = (byte)(i & 0xFF);
    }
    try {
      String b64 = CryptoUtils.digest(data, "SHA");
      assertEquals("WwBmnEgNXP+9+ovbqZVhFg8tG3c=", b64);
    } catch (CryptoException e) {
      assertEquals("", e.getMessage());
    }
  }

  public void testRsaoaep() {
    String text = "test";
     
    try {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
      keyGen.initialize(1024, new SecureRandom());
      KeyPair kp = keyGen.generateKeyPair();
      RSAPublicKey rsaPublicKey = (RSAPublicKey)kp.getPublic();
      String b64EncodedData = CryptoUtils.rsaoaepEncrypt(text.getBytes(), rsaPublicKey);
      
      byte[] decrypted = CryptoUtils.decryptRSAOAEP(b64EncodedData, kp.getPrivate());
      assertEquals(text, new String(decrypted));
    } catch (NoSuchAlgorithmException e) {
      assertEquals("", e.getMessage());
    } catch (CryptoException e) {
      assertEquals("", e.getMessage());
    }
  }

  public void testSignVerify() {
    String text = "test";
    try {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
      keyGen.initialize(1024, new SecureRandom());
      KeyPair kp = keyGen.generateKeyPair();
          String signingAlgorithm = "SHA1withRSA";
      String b64signature = CryptoUtils.sign(text.getBytes(), kp.getPrivate(), signingAlgorithm);
      RSAPublicKey publicKey = (RSAPublicKey) kp.getPublic();
      byte[] signature = Base64.decode(b64signature);
      
      boolean verified = CryptoUtils.verifyRSA(text.getBytes(), signature, 
          publicKey.getModulus(), publicKey.getPublicExponent(), "SHA");
      assertTrue(verified);
    } catch (NoSuchAlgorithmException e) {
      assertEquals("", e.getMessage());
    } catch (CryptoException e) {
      assertEquals("", e.getMessage());
    }
  }

  public void testSignVerifyLength() {
    String text = "test";
    try {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
      keyGen.initialize(1024, new SecureRandom());
      KeyPair kp = keyGen.generateKeyPair();
      RSAPrivateKey privateKey = (RSAPrivateKey)kp.getPrivate();
      assertEquals(1024, privateKey.getModulus().bitLength());
          String signingAlgorithm = "SHA1withRSA";
      String b64signature = CryptoUtils.sign(text.getBytes(), privateKey, signingAlgorithm);
      assertEquals(172, b64signature.length());
      byte[] signature = Base64.decode(b64signature);
      assertEquals(1024 / 8, signature.length);

      RSAPublicKey publicKey = (RSAPublicKey) kp.getPublic();
      // the following must not always be true.
      // but must be true for CardSpace
      assertEquals(65537, publicKey.getPublicExponent().longValue());
      boolean verified = CryptoUtils.verifyRSA(text.getBytes(), signature, 
          publicKey.getModulus(), publicKey.getPublicExponent(), "SHA");
      assertTrue(verified);
    } catch (NoSuchAlgorithmException e) {
      assertEquals("", e.getMessage());
    } catch (CryptoException e) {
      assertEquals("", e.getMessage());
    }
  }

  public void testSignVerifyStatic() {
    String text = "test";
    try {
      PrivateKey privateKey = XmldapCertsAndKeys.getXmldapPrivateKey();
      String signingAlgorithm = "SHA1withRSA";
      String b64signature = CryptoUtils.sign(text.getBytes(), privateKey, signingAlgorithm);
      assertEquals("rxEfBXFsfPsb+cxYZZcn359NLeSPkN6BA+JKXe+VwRJVA96pV1gvshSe6e" +
          "/2uox14lO5UR6EugDGiDIH9Kx7MeINKOw6+bzMirPh3FGUnWVXDv/sxafd4/gYP" +
          "hcB+UlN184nUqQHUtc8ZV3l+p5yaMuLeVDYTsqgrHvdYroZH8nKAIWcmFC6QT21" +
          "ua+ibqzUn53JA0HTG9mrFJtwT9O8Vmgc0dOnUZ/Nn07JgwuQXi7sPKZdb1G2j7x" +
          "M1vGQUo6RXwuvJOqk9eoyC4Kxi75E/YGHAGqQssHvJ5UIcBPMI8PjokG3i2536n" +
          "LWQjkQcj4F0Mw8p1kZg0gP0IcTQ8sUIg==", b64signature);
      byte[] signature = Base64.decode(b64signature);
      X509Certificate cert = XmldapCertsAndKeys.getXmldapCert();
      RSAPublicKey publicKey = (RSAPublicKey) cert.getPublicKey();
      
      boolean verified = CryptoUtils.verifyRSA(text.getBytes(), signature, 
          publicKey.getModulus(), publicKey.getPublicExponent(), "SHA");
      assertTrue(verified);
    } catch (NoSuchAlgorithmException e) {
      assertEquals("", e.getMessage());
    } catch (CryptoException e) {
      assertEquals("", e.getMessage());
    } catch (InvalidKeySpecException e) {
      assertEquals("", e.getMessage());
    } catch (CertificateException e) {
      assertEquals("", e.getMessage());
    }
  }

    public void testX509fromB64() throws CertificateException, CryptoException {
      X509Certificate certIn = XmldapCertsAndKeys.getXmldapCert();
      String b64EncodedX509Certificate = Base64.encodeBytesNoBreaks(certIn.getEncoded());
      X509Certificate certOut = CryptoUtils.X509fromB64(b64EncodedX509Certificate);
      assertTrue(certIn.equals(certOut));
    }

    public void testNimbusConcatKDF_8args384() throws Exception {
      String hashAlg = "SHA-384";
      byte[] z = "this is the secrect key phrase".getBytes();
      int keyDataLen = 256;
      byte[] algorithmID = {};
      byte[] partyUInfo = {};
      byte[] partyVInfo = {};
      byte[] suppPubInfo = null;
      byte[] suppPrivInfo = null;
      byte[] result = ConcatKeyDerivationFunction.concatKDF(hashAlg, z, keyDataLen, algorithmID, partyUInfo, partyVInfo, suppPubInfo, suppPrivInfo);
      assertEquals("1LBfs0NBIPu1vfgnjYNMrSvBA/IJOlpwMgamYR9VnPA=", Base64.encodeBytesNoBreaks(result));
  }

//    public void testNimbusConcatKDF_8args256() throws Exception {
//      String hashAlg = "SHA-256";
//      byte[] z = "this is the secrect key phrase".getBytes();
//      int keyDataLen = 256;
//      byte[] algorithmID = {};
//      byte[] partyUInfo = {};
//      byte[] partyVInfo = {};
//      byte[] suppPubInfo = null;
//      byte[] suppPrivInfo = null;
//      byte[] result = ConcatKeyDerivationFunction.concatKDF(hashAlg, z, keyDataLen, algorithmID, partyUInfo, partyVInfo, suppPubInfo, suppPrivInfo);
//      assertEquals("", Base64.encodeBytesNoBreaks(result));
//  }

    public void testConcatKdf256() throws Exception {
      Digest kdfDigest = new SHA256Digest();
      byte[] zBytes = "this is the secrect key phrase".getBytes();
      KDFConcatGenerator kdfConcatGenerator = new KDFConcatGenerator(kdfDigest);
      kdfConcatGenerator.init(new KDFParameters(zBytes, null));
      int keylength = 32;
      byte[] out = new byte[keylength];
      kdfConcatGenerator.generateBytes(out, 0, out.length);
      assertEquals("dU3Oi625alXZTTVSVaNiAtC47nQfYr591+KbRBwCwT4=", Base64.encodeBytesNoBreaks(out));
    }
    
    public void testConcatKdf256_64() throws Exception {
      Digest kdfDigest = new SHA256Digest();
      byte[] zBytes = "this is the secrect key phrase".getBytes();
      KDFConcatGenerator kdfConcatGenerator = new KDFConcatGenerator(kdfDigest);
      kdfConcatGenerator.init(new KDFParameters(zBytes, null));
      int keylength = 64;
      byte[] out = new byte[keylength];
      kdfConcatGenerator.generateBytes(out, 0, out.length);
      assertEquals("dU3Oi625alXZTTVSVaNiAtC47nQfYr591+KbRBwCwT7dsTpOPFNykjM/aw62LnEdLr7sq08sjvXGS9qFEGucjw==", Base64.encodeBytesNoBreaks(out));
    }
    
    public void testConcatKdf384() throws Exception {
      Digest kdfDigest = new SHA384Digest();
      byte[] zBytes = "this is the secrect key phrase".getBytes();
      KDFConcatGenerator kdfConcatGenerator = new KDFConcatGenerator(kdfDigest);
      kdfConcatGenerator.init(new KDFParameters(zBytes, null));
      int keylength = 32;
      byte[] out = new byte[keylength];
      kdfConcatGenerator.generateBytes(out, 0, out.length);
      assertEquals("1LBfs0NBIPu1vfgnjYNMrSvBA/IJOlpwMgamYR9VnPA=", Base64.encodeBytesNoBreaks(out));
    }
    
    public void testConcatKdf384_48() throws Exception {
      Digest kdfDigest = new SHA384Digest();
      byte[] zBytes = "this is the secrect key phrase".getBytes();
      KDFConcatGenerator kdfConcatGenerator = new KDFConcatGenerator(kdfDigest);
      kdfConcatGenerator.init(new KDFParameters(zBytes, null));
      int keylength = 48;
      byte[] out = new byte[keylength];
      kdfConcatGenerator.generateBytes(out, 0, out.length);
      assertEquals("1LBfs0NBIPu1vfgnjYNMrSvBA/IJOlpwMgamYR9VnPA1Tx4RwhcHFlSdsDdWR7bd", Base64.encodeBytesNoBreaks(out));
    }
    
//    public void testConcatKdfXmldapVsNimbus256() throws Exception {
//      Digest kdfDigest = new SHA256Digest();
//      byte[] zBytes = "this is the secrect key phrase".getBytes();
//      KDFConcatGenerator kdfConcatGenerator = new KDFConcatGenerator(kdfDigest);
//      kdfConcatGenerator.init(new KDFParameters(zBytes, null));
//      int keylength = 32;
//      byte[] out = new byte[keylength];
//      kdfConcatGenerator.generateBytes(out, 0, out.length);
//      assertEquals("dU3Oi625alXZTTVSVaNiAtC47nQfYr591+KbRBwCwT4=", Base64.encodeBytesNoBreaks(out));
//      
//      String hashAlg = "SHA-256";
//      int keyDataLen = 256;
//      byte[] algorithmID = {};
//      byte[] partyUInfo = {};
//      byte[] partyVInfo = {};
//      byte[] suppPubInfo = null;
//      byte[] suppPrivInfo = null;
//      byte[] result = ConcatKeyDerivationFunction.concatKDF(hashAlg, zBytes, keyDataLen, algorithmID, partyUInfo, partyVInfo, suppPubInfo, suppPrivInfo);
//      assertEquals("dU3Oi625alXZTTVSVaNiAtC47nQfYr591+KbRBwCwT4=", Base64.encodeBytesNoBreaks(result));
//    }
    
    public void testConcatKdfXmldapVsNimbus384() throws Exception {
      final String expected = "1LBfs0NBIPu1vfgnjYNMrSvBA/IJOlpwMgamYR9VnPA=";
      Digest kdfDigest = new SHA384Digest();
      byte[] zBytes = "this is the secrect key phrase".getBytes();
      KDFConcatGenerator kdfConcatGenerator = new KDFConcatGenerator(kdfDigest);
      kdfConcatGenerator.init(new KDFParameters(zBytes, null));
      int keylength = 32;
      byte[] out = new byte[keylength];
      kdfConcatGenerator.generateBytes(out, 0, out.length);
      assertEquals(expected, Base64.encodeBytesNoBreaks(out));
      
      String hashAlg = "SHA-384";
      int keyDataLen = 256;
      byte[] algorithmID = {};
      byte[] partyUInfo = {};
      byte[] partyVInfo = {};
      byte[] suppPubInfo = null;
      byte[] suppPrivInfo = null;
      byte[] result = ConcatKeyDerivationFunction.concatKDF(hashAlg, zBytes, keyDataLen, algorithmID, partyUInfo, partyVInfo, suppPubInfo, suppPrivInfo);
      assertEquals(expected, Base64.encodeBytesNoBreaks(result));
    }
}
