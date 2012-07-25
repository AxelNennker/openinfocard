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

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
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
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
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
    for (int i = 0; i < data.length; i++) {
      data[i] = (byte) (i & 0xFF);
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
    for (int i = 0; i < data.length; i++) {
      data[i] = (byte) (i & 0xFF);
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
      RSAPublicKey rsaPublicKey = (RSAPublicKey) kp.getPublic();
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

      boolean verified = CryptoUtils.verifyRSA(text.getBytes(), signature, publicKey.getModulus(),
          publicKey.getPublicExponent(), "SHA");
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
      RSAPrivateKey privateKey = (RSAPrivateKey) kp.getPrivate();
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
      boolean verified = CryptoUtils.verifyRSA(text.getBytes(), signature, publicKey.getModulus(),
          publicKey.getPublicExponent(), "SHA");
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
      assertEquals("rxEfBXFsfPsb+cxYZZcn359NLeSPkN6BA+JKXe+VwRJVA96pV1gvshSe6e"
          + "/2uox14lO5UR6EugDGiDIH9Kx7MeINKOw6+bzMirPh3FGUnWVXDv/sxafd4/gYP"
          + "hcB+UlN184nUqQHUtc8ZV3l+p5yaMuLeVDYTsqgrHvdYroZH8nKAIWcmFC6QT21"
          + "ua+ibqzUn53JA0HTG9mrFJtwT9O8Vmgc0dOnUZ/Nn07JgwuQXi7sPKZdb1G2j7x"
          + "M1vGQUo6RXwuvJOqk9eoyC4Kxi75E/YGHAGqQssHvJ5UIcBPMI8PjokG3i2536n" + "LWQjkQcj4F0Mw8p1kZg0gP0IcTQ8sUIg==",
          b64signature);
      byte[] signature = Base64.decode(b64signature);
      X509Certificate cert = XmldapCertsAndKeys.getXmldapCert();
      RSAPublicKey publicKey = (RSAPublicKey) cert.getPublicKey();

      boolean verified = CryptoUtils.verifyRSA(text.getBytes(), signature, publicKey.getModulus(),
          publicKey.getPublicExponent(), "SHA");
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
    byte[] result = ConcatKeyDerivationFunction.concatKDF(hashAlg, z, keyDataLen, algorithmID, partyUInfo, partyVInfo,
        suppPubInfo, suppPrivInfo);
    assertEquals("1LBfs0NBIPu1vfgnjYNMrSvBA/IJOlpwMgamYR9VnPA=", Base64.encodeBytesNoBreaks(result));
  }

  public void testNimbusConcatKDF_8args256() throws Exception {
    String hashAlg = "SHA-256";
    byte[] z = "this is the secrect key phrase".getBytes();
    int keyDataLen = 256;
    byte[] algorithmID = {};
    byte[] partyUInfo = {};
    byte[] partyVInfo = {};
    byte[] suppPubInfo = null;
    byte[] suppPrivInfo = null;
    byte[] result = ConcatKeyDerivationFunction.concatKDF(hashAlg, z, keyDataLen, algorithmID, partyUInfo, partyVInfo,
        suppPubInfo, suppPrivInfo);
    assertEquals("dU3Oi625alXZTTVSVaNiAtC47nQfYr591+KbRBwCwT4=", Base64.encodeBytesNoBreaks(result));
  }

  public void testConcatKdf256() throws Exception {
    Digest kdfDigest = new SHA256Digest();
    byte[] zBytes = "this is the secrect key phrase".getBytes();
    KDFConcatGenerator kdfConcatGenerator = new KDFConcatGenerator(kdfDigest, new byte[] {});
    kdfConcatGenerator.init(new KDFParameters(zBytes, null));
    int keylength = 32;
    byte[] out = new byte[keylength];
    kdfConcatGenerator.generateBytes(out, 0, out.length);
    assertEquals("dU3Oi625alXZTTVSVaNiAtC47nQfYr591+KbRBwCwT4=", Base64.encodeBytesNoBreaks(out));
  }

  public void testConcatKdf256Example1() throws Exception {
    Digest kdfDigest = new SHA256Digest();
    byte[] zBytes = { 4, (byte) 211, 31, (byte) 197, 84, (byte) 157, (byte) 252, (byte) 254, 11, 100, (byte) 157,
        (byte) 250, 63, (byte) 170, 106, (byte) 206, 107, 124, (byte) 212, 45, 111, 107, 9, (byte) 219, (byte) 200,
        (byte) 177, 0, (byte) 240, (byte) 143, (byte) 156, 44, (byte) 207 };
    byte[] otherInfo = { 69, 110, 99, 114, 121, 112, 116, 105, 111, 110 };
    KDFConcatGenerator kdfConcatGenerator = new KDFConcatGenerator(kdfDigest, otherInfo);
    kdfConcatGenerator.init(new KDFParameters(zBytes, null));
    int keylength = 32;
    byte[] out = new byte[keylength];
    kdfConcatGenerator.generateBytes(out, 0, out.length);
    byte[] CEK1 = { (byte) 249, (byte) 255, 87, (byte) 218, (byte) 224, (byte) 223, (byte) 221, 53, (byte) 204, 121,
        (byte) 166, (byte) 130, (byte) 195, (byte) 184, 50, 69, 11, (byte) 237, (byte) 202, 71, 10, 96, 59, (byte) 199,
        (byte) 140, 88, 126, (byte) 147, (byte) 146, 113, (byte) 222, 41 };
    String expectedB64 = Base64.encodeBytesNoBreaks(CEK1);
    assertEquals(expectedB64, Base64.encodeBytesNoBreaks(out));

    byte[] otherInfoIntegrity = { 73, 110, 116, 101, 103, 114, 105, 116, 121 };
    kdfConcatGenerator = new KDFConcatGenerator(kdfDigest, otherInfoIntegrity);
    kdfConcatGenerator.init(new KDFParameters(zBytes, null));
    out = new byte[keylength];
    kdfConcatGenerator.generateBytes(out, 0, out.length);
    byte[] CIK1 = { (byte) 218, (byte) 209, (byte) 130, 50, (byte) 169, 45, 70, (byte) 214, 29, (byte) 187, 123, 20, 3,
        (byte) 158, 111, 122, (byte) 182, 94, 57, (byte) 133, (byte) 245, 76, 97, 44, (byte) 193, 80, 81, (byte) 246,
        115, (byte) 177, (byte) 225, (byte) 159 };
    expectedB64 = Base64.encodeBytesNoBreaks(CIK1);
    assertEquals(expectedB64, Base64.encodeBytesNoBreaks(out));

  }

  public void testConcatKdfExample2CEK() throws Exception {
    Digest kdfDigest = new SHA256Digest();
    byte[] CMK2 = { (byte) 148, (byte) 116, (byte) 199, (byte) 126, (byte) 2, (byte) 117, (byte) 233, (byte) 76,
        (byte) 150, (byte) 149, (byte) 89, (byte) 193, (byte) 61, (byte) 34, (byte) 239, (byte) 226, (byte) 109,
        (byte) 71, (byte) 59, (byte) 160, (byte) 192, (byte) 140, (byte) 150, (byte) 235, (byte) 106, (byte) 204,
        (byte) 49, (byte) 176, (byte) 68, (byte) 119, (byte) 13, (byte) 34, (byte) 49, (byte) 19, (byte) 41, (byte) 69,
        (byte) 5, (byte) 20, (byte) 252, (byte) 145, (byte) 104, (byte) 129, (byte) 137, (byte) 138, (byte) 67,
        (byte) 23, (byte) 153, (byte) 83, (byte) 81, (byte) 234, (byte) 82, (byte) 247, (byte) 48, (byte) 211,
        (byte) 41, (byte) 130, (byte) 35, (byte) 124, (byte) 45, (byte) 156, (byte) 249, (byte) 7, (byte) 225,
        (byte) 168 };
    byte[] otherInfo = { 69, 110, 99, 114, 121, 112, 116, 105, 111, 110 };
    KDFConcatGenerator kdfConcatGenerator = new KDFConcatGenerator(kdfDigest, otherInfo);
    kdfConcatGenerator.init(new KDFParameters(CMK2, null));
    int keylength = 16;
    byte[] out = new byte[keylength];
    kdfConcatGenerator.generateBytes(out, 0, out.length);
    byte[] CEK2 = { (byte) 137, 5, 92, 9, 17, 47, 17, 86, (byte) 253, (byte) 235, 34, (byte) 247, 121, 78, 11,
        (byte) 144 };
    String expectedB64 = Base64.encodeBytesNoBreaks(CEK2);
    assertEquals(expectedB64, Base64.encodeBytesNoBreaks(out));
  }

  public void testConcatKdfExample2CIK() throws Exception {
    Digest kdfDigest = new SHA256Digest();
    byte[] CMK2 = { (byte) 148, (byte) 116, (byte) 199, (byte) 126, (byte) 2, (byte) 117, (byte) 233, (byte) 76,
        (byte) 150, (byte) 149, (byte) 89, (byte) 193, (byte) 61, (byte) 34, (byte) 239, (byte) 226, (byte) 109,
        (byte) 71, (byte) 59, (byte) 160, (byte) 192, (byte) 140, (byte) 150, (byte) 235, (byte) 106, (byte) 204,
        (byte) 49, (byte) 176, (byte) 68, (byte) 119, (byte) 13, (byte) 34, (byte) 49, (byte) 19, (byte) 41, (byte) 69,
        (byte) 5, (byte) 20, (byte) 252, (byte) 145, (byte) 104, (byte) 129, (byte) 137, (byte) 138, (byte) 67,
        (byte) 23, (byte) 153, (byte) 83, (byte) 81, (byte) 234, (byte) 82, (byte) 247, (byte) 48, (byte) 211,
        (byte) 41, (byte) 130, (byte) 35, (byte) 124, (byte) 45, (byte) 156, (byte) 249, (byte) 7, (byte) 225,
        (byte) 168 };
    byte[] otherInfo = { 73, 110, 116, 101, 103, 114, 105, 116, 121 };
    KDFConcatGenerator kdfConcatGenerator = new KDFConcatGenerator(kdfDigest, otherInfo);
    kdfConcatGenerator.init(new KDFParameters(CMK2, null));
    int keylength = 64;
    byte[] out = new byte[keylength];
    kdfConcatGenerator.generateBytes(out, 0, out.length);
    byte[] CIK2 = { (byte) 11, (byte) 179, (byte) 132, (byte) 177, (byte) 171, (byte) 24, (byte) 126, (byte) 19,
        (byte) 113, (byte) 1, (byte) 200, (byte) 102, (byte) 100, (byte) 74, (byte) 88, (byte) 149, (byte) 31,
        (byte) 41, (byte) 71, (byte) 57, (byte) 51, (byte) 179, (byte) 106, (byte) 242, (byte) 113, (byte) 211,
        (byte) 56, (byte) 56, (byte) 37, (byte) 198, (byte) 57, (byte) 17, (byte) 149, (byte) 209, (byte) 221,
        (byte) 113, (byte) 40, (byte) 191, (byte) 95, (byte) 252, (byte) 142, (byte) 254, (byte) 141, (byte) 230,
        (byte) 39, (byte) 113, (byte) 139, (byte) 84, (byte) 44, (byte) 156, (byte) 247, (byte) 47, (byte) 223,
        (byte) 101, (byte) 229, (byte) 180, (byte) 82, (byte) 231, (byte) 38, (byte) 96, (byte) 170, (byte) 119,
        (byte) 236, (byte) 81 };
    String expectedB64 = Base64.encodeBytesNoBreaks(CIK2);
    assertEquals(expectedB64, Base64.encodeBytesNoBreaks(out));
  }

  public void testConcatKdf256OtherInfo() throws Exception {
    Digest kdfDigest = new SHA256Digest();
    byte[] zBytes = { 4, (byte) 211, 31, (byte) 197, 84, (byte) 157, (byte) 252, (byte) 254, 11, 100, (byte) 157,
        (byte) 250, 63, (byte) 170, 106, (byte) 206, 107, 124, (byte) 212, 45, 111, 107, 9, (byte) 219, (byte) 200,
        (byte) 177, 0, (byte) 240, (byte) 143, (byte) 156, 44, (byte) 207 };
    byte[] otherInfo = { 69, 110, 99, 114, 121, 112, 116, 105, 111, 110 };
    KDFConcatGenerator kdfConcatGenerator = new KDFConcatGenerator(kdfDigest, otherInfo);
    kdfConcatGenerator.init(new KDFParameters(zBytes, null));
    int keylength = 32;
    byte[] out = new byte[keylength];
    kdfConcatGenerator.generateBytes(out, 0, out.length);
    assertEquals("+f9X2uDf3TXMeaaCw7gyRQvtykcKYDvHjFh+k5Jx3ik=", Base64.encodeBytesNoBreaks(out));
  }

  public void testConcatKdf256_64() throws Exception {
    Digest kdfDigest = new SHA256Digest();
    byte[] zBytes = "this is the secrect key phrase".getBytes();
    KDFConcatGenerator kdfConcatGenerator = new KDFConcatGenerator(kdfDigest, new byte[] {});
    kdfConcatGenerator.init(new KDFParameters(zBytes, null));
    int keylength = 64;
    byte[] out = new byte[keylength];
    kdfConcatGenerator.generateBytes(out, 0, out.length);
    assertEquals("dU3Oi625alXZTTVSVaNiAtC47nQfYr591+KbRBwCwT7dsTpOPFNykjM/aw62LnEdLr7sq08sjvXGS9qFEGucjw==",
        Base64.encodeBytesNoBreaks(out));
  }

  public void testConcatKdf384() throws Exception {
    Digest kdfDigest = new SHA384Digest();
    byte[] zBytes = "this is the secrect key phrase".getBytes();
    KDFConcatGenerator kdfConcatGenerator = new KDFConcatGenerator(kdfDigest, new byte[] {});
    kdfConcatGenerator.init(new KDFParameters(zBytes, null));
    int keylength = 32;
    byte[] out = new byte[keylength];
    kdfConcatGenerator.generateBytes(out, 0, out.length);
    assertEquals("1LBfs0NBIPu1vfgnjYNMrSvBA/IJOlpwMgamYR9VnPA=", Base64.encodeBytesNoBreaks(out));
  }

  public void testConcatKdf384_48() throws Exception {
    Digest kdfDigest = new SHA384Digest();
    byte[] zBytes = "this is the secrect key phrase".getBytes();
    KDFConcatGenerator kdfConcatGenerator = new KDFConcatGenerator(kdfDigest, new byte[] {});
    kdfConcatGenerator.init(new KDFParameters(zBytes, null));
    int keylength = 48;
    byte[] out = new byte[keylength];
    kdfConcatGenerator.generateBytes(out, 0, out.length);
    assertEquals("1LBfs0NBIPu1vfgnjYNMrSvBA/IJOlpwMgamYR9VnPA1Tx4RwhcHFlSdsDdWR7bd", Base64.encodeBytesNoBreaks(out));
  }

  public void testConcatKdfXmldapVsNimbus256() throws Exception {
    Digest kdfDigest = new SHA256Digest();
    byte[] zBytes = "this is the secrect key phrase".getBytes();
    KDFConcatGenerator kdfConcatGenerator = new KDFConcatGenerator(kdfDigest, new byte[] {});
    kdfConcatGenerator.init(new KDFParameters(zBytes, null));
    int keylength = 32;
    byte[] out = new byte[keylength];
    kdfConcatGenerator.generateBytes(out, 0, out.length);
    assertEquals("dU3Oi625alXZTTVSVaNiAtC47nQfYr591+KbRBwCwT4=", Base64.encodeBytesNoBreaks(out));

    String hashAlg = "SHA-256";
    int keyDataLen = 256;
    byte[] algorithmID = {};
    byte[] partyUInfo = {};
    byte[] partyVInfo = {};
    byte[] suppPubInfo = null;
    byte[] suppPrivInfo = null;
    byte[] result = ConcatKeyDerivationFunction.concatKDF(hashAlg, zBytes, keyDataLen, algorithmID, partyUInfo,
        partyVInfo, suppPubInfo, suppPrivInfo);
    assertEquals("dU3Oi625alXZTTVSVaNiAtC47nQfYr591+KbRBwCwT4=", Base64.encodeBytesNoBreaks(result));
  }

  public void testConcatKdfXmldapVsNimbus384() throws Exception {
    // final String expected = "1LBfs0NBIPu1vfgnjYNMrSvBA/IJOlpwMgamYR9VnPA=";
    Digest kdfDigest = new SHA384Digest();
    byte[] zBytes = "this is the secrect key phrase".getBytes();
    KDFConcatGenerator kdfConcatGenerator = new KDFConcatGenerator(kdfDigest, new byte[] {});
    kdfConcatGenerator.init(new KDFParameters(zBytes, null));
    int keylength = 32;
    byte[] out = new byte[keylength];
    kdfConcatGenerator.generateBytes(out, 0, out.length);

    String hashAlg = "SHA-384";
    int keyDataLen = 256;
    byte[] algorithmID = {};
    byte[] partyUInfo = {};
    byte[] partyVInfo = {};
    byte[] suppPubInfo = null;
    byte[] suppPrivInfo = null;
    byte[] result = ConcatKeyDerivationFunction.concatKDF(hashAlg, zBytes, keyDataLen, algorithmID, partyUInfo,
        partyVInfo, suppPubInfo, suppPrivInfo);
    assertEquals(Base64.encodeBytesNoBreaks(out), Base64.encodeBytesNoBreaks(result));
  }

  public void testrsaoaepEncryptBytes() throws Exception {
    byte[] cmk = { (byte) 177, (byte) 161, (byte) 244, (byte) 128, (byte) 84, (byte) 143, (byte) 225, (byte) 115,
        (byte) 63, (byte) 180, (byte) 3, (byte) 255, (byte) 107, (byte) 154, (byte) 212, (byte) 246, (byte) 138,
        (byte) 7, (byte) 110, (byte) 91, (byte) 112, (byte) 46, (byte) 34, (byte) 105, (byte) 47, (byte) 130,
        (byte) 203, (byte) 46, (byte) 122, (byte) 234, (byte) 64, (byte) 252 };

    final byte[] n = { (byte) 161, (byte) 168, (byte) 84, (byte) 34, (byte) 133, (byte) 176, (byte) 208, (byte) 173,
        (byte) 46, (byte) 176, (byte) 163, (byte) 110, (byte) 57, (byte) 30, (byte) 135, (byte) 227, (byte) 9,
        (byte) 31, (byte) 226, (byte) 128, (byte) 84, (byte) 92, (byte) 116, (byte) 241, (byte) 70, (byte) 248,
        (byte) 27, (byte) 227, (byte) 193, (byte) 62, (byte) 5, (byte) 91, (byte) 241, (byte) 145, (byte) 224,
        (byte) 205, (byte) 141, (byte) 176, (byte) 184, (byte) 133, (byte) 239, (byte) 43, (byte) 81, (byte) 103,
        (byte) 9, (byte) 161, (byte) 153, (byte) 157, (byte) 179, (byte) 104, (byte) 123, (byte) 51, (byte) 189,
        (byte) 34, (byte) 152, (byte) 69, (byte) 97, (byte) 69, (byte) 78, (byte) 93, (byte) 140, (byte) 131,
        (byte) 87, (byte) 182, (byte) 169, (byte) 101, (byte) 92, (byte) 142, (byte) 3, (byte) 22, (byte) 167,
        (byte) 8, (byte) 212, (byte) 56, (byte) 35, (byte) 79, (byte) 210, (byte) 222, (byte) 192, (byte) 208,
        (byte) 252, (byte) 49, (byte) 109, (byte) 138, (byte) 173, (byte) 253, (byte) 210, (byte) 166, (byte) 201,
        (byte) 63, (byte) 102, (byte) 74, (byte) 5, (byte) 158, (byte) 41, (byte) 90, (byte) 144, (byte) 108,
        (byte) 160, (byte) 79, (byte) 10, (byte) 89, (byte) 222, (byte) 231, (byte) 172, (byte) 31, (byte) 227,
        (byte) 197, (byte) 0, (byte) 19, (byte) 72, (byte) 81, (byte) 138, (byte) 78, (byte) 136, (byte) 221,
        (byte) 121, (byte) 118, (byte) 196, (byte) 17, (byte) 146, (byte) 10, (byte) 244, (byte) 188, (byte) 72,
        (byte) 113, (byte) 55, (byte) 221, (byte) 162, (byte) 217, (byte) 171, (byte) 27, (byte) 57, (byte) 233,
        (byte) 210, (byte) 101, (byte) 236, (byte) 154, (byte) 199, (byte) 56, (byte) 138, (byte) 239, (byte) 101,
        (byte) 48, (byte) 198, (byte) 186, (byte) 202, (byte) 160, (byte) 76, (byte) 111, (byte) 234, (byte) 71,
        (byte) 57, (byte) 183, (byte) 5, (byte) 211, (byte) 171, (byte) 136, (byte) 126, (byte) 64, (byte) 40,
        (byte) 75, (byte) 58, (byte) 89, (byte) 244, (byte) 254, (byte) 107, (byte) 84, (byte) 103, (byte) 7,
        (byte) 236, (byte) 69, (byte) 163, (byte) 18, (byte) 180, (byte) 251, (byte) 58, (byte) 153, (byte) 46,
        (byte) 151, (byte) 174, (byte) 12, (byte) 103, (byte) 197, (byte) 181, (byte) 161, (byte) 162, (byte) 55,
        (byte) 250, (byte) 235, (byte) 123, (byte) 110, (byte) 17, (byte) 11, (byte) 158, (byte) 24, (byte) 47,
        (byte) 133, (byte) 8, (byte) 199, (byte) 235, (byte) 107, (byte) 126, (byte) 130, (byte) 246, (byte) 73,
        (byte) 195, (byte) 20, (byte) 108, (byte) 202, (byte) 176, (byte) 214, (byte) 187, (byte) 45, (byte) 146,
        (byte) 182, (byte) 118, (byte) 54, (byte) 32, (byte) 200, (byte) 61, (byte) 201, (byte) 71, (byte) 243,
        (byte) 1, (byte) 255, (byte) 131, (byte) 84, (byte) 37, (byte) 111, (byte) 211, (byte) 168, (byte) 228,
        (byte) 45, (byte) 192, (byte) 118, (byte) 27, (byte) 197, (byte) 235, (byte) 232, (byte) 36, (byte) 10,
        (byte) 230, (byte) 248, (byte) 190, (byte) 82, (byte) 182, (byte) 140, (byte) 35, (byte) 204, (byte) 108,
        (byte) 190, (byte) 253, (byte) 186, (byte) 186, (byte) 27 };
    final byte[] e = { 1, 0, 1 };
    final byte[] d = { (byte) 144, (byte) 183, (byte) 109, (byte) 34, (byte) 62, (byte) 134, (byte) 108, (byte) 57,
        (byte) 44, (byte) 252, (byte) 10, (byte) 66, (byte) 73, (byte) 54, (byte) 16, (byte) 181, (byte) 233,
        (byte) 92, (byte) 54, (byte) 219, (byte) 101, (byte) 42, (byte) 35, (byte) 178, (byte) 63, (byte) 51,
        (byte) 43, (byte) 92, (byte) 119, (byte) 136, (byte) 251, (byte) 41, (byte) 53, (byte) 23, (byte) 191,
        (byte) 164, (byte) 164, (byte) 60, (byte) 88, (byte) 227, (byte) 229, (byte) 152, (byte) 228, (byte) 213,
        (byte) 149, (byte) 228, (byte) 169, (byte) 237, (byte) 104, (byte) 71, (byte) 151, (byte) 75, (byte) 88,
        (byte) 252, (byte) 216, (byte) 77, (byte) 251, (byte) 231, (byte) 28, (byte) 97, (byte) 88, (byte) 193,
        (byte) 215, (byte) 202, (byte) 248, (byte) 216, (byte) 121, (byte) 195, (byte) 211, (byte) 245, (byte) 250,
        (byte) 112, (byte) 71, (byte) 243, (byte) 61, (byte) 129, (byte) 95, (byte) 39, (byte) 244, (byte) 122,
        (byte) 225, (byte) 217, (byte) 169, (byte) 211, (byte) 165, (byte) 48, (byte) 253, (byte) 220, (byte) 59,
        (byte) 122, (byte) 219, (byte) 42, (byte) 86, (byte) 223, (byte) 32, (byte) 236, (byte) 39, (byte) 48,
        (byte) 103, (byte) 78, (byte) 122, (byte) 216, (byte) 187, (byte) 88, (byte) 176, (byte) 89, (byte) 24,
        (byte) 1, (byte) 42, (byte) 177, (byte) 24, (byte) 99, (byte) 142, (byte) 170, (byte) 1, (byte) 146, (byte) 43,
        (byte) 3, (byte) 108, (byte) 64, (byte) 194, (byte) 121, (byte) 182, (byte) 95, (byte) 187, (byte) 134,
        (byte) 71, (byte) 88, (byte) 96, (byte) 134, (byte) 74, (byte) 131, (byte) 167, (byte) 69, (byte) 106,
        (byte) 143, (byte) 121, (byte) 27, (byte) 72, (byte) 44, (byte) 245, (byte) 95, (byte) 39, (byte) 194,
        (byte) 179, (byte) 175, (byte) 203, (byte) 122, (byte) 16, (byte) 112, (byte) 183, (byte) 17, (byte) 200,
        (byte) 202, (byte) 31, (byte) 17, (byte) 138, (byte) 156, (byte) 184, (byte) 210, (byte) 157, (byte) 184,
        (byte) 154, (byte) 131, (byte) 128, (byte) 110, (byte) 12, (byte) 85, (byte) 195, (byte) 122, (byte) 241,
        (byte) 79, (byte) 251, (byte) 229, (byte) 183, (byte) 117, (byte) 21, (byte) 123, (byte) 133, (byte) 142,
        (byte) 220, (byte) 153, (byte) 9, (byte) 59, (byte) 57, (byte) 105, (byte) 81, (byte) 255, (byte) 138,
        (byte) 77, (byte) 82, (byte) 54, (byte) 62, (byte) 216, (byte) 38, (byte) 249, (byte) 208, (byte) 17,
        (byte) 197, (byte) 49, (byte) 45, (byte) 19, (byte) 232, (byte) 157, (byte) 251, (byte) 131, (byte) 137,
        (byte) 175, (byte) 72, (byte) 126, (byte) 43, (byte) 229, (byte) 69, (byte) 179, (byte) 117, (byte) 82,
        (byte) 157, (byte) 213, (byte) 83, (byte) 35, (byte) 57, (byte) 210, (byte) 197, (byte) 252, (byte) 171,
        (byte) 143, (byte) 194, (byte) 11, (byte) 47, (byte) 163, (byte) 6, (byte) 253, (byte) 75, (byte) 252,
        (byte) 96, (byte) 11, (byte) 187, (byte) 84, (byte) 130, (byte) 210, (byte) 7, (byte) 121, (byte) 78,
        (byte) 91, (byte) 79, (byte) 57, (byte) 251, (byte) 138, (byte) 132, (byte) 220, (byte) 60, (byte) 224,
        (byte) 173, (byte) 56, (byte) 224, (byte) 201 };

    BigInteger N = new BigInteger(1, n);
    BigInteger E = new BigInteger(1, e);
    BigInteger D = new BigInteger(1, d);

    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(N, E);
    RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(N, D);
    RSAPublicKey aRsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);
    RSAPrivateKey aRsaPrivKey = (RSAPrivateKey) keyFactory.generatePrivate(privKeySpec);

    BouncyCastleProvider bc = new BouncyCastleProvider();
    // Security.addProvider(bc);
    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", "SunJCE");
    cipher.init(Cipher.ENCRYPT_MODE, aRsaPublicKey);
    byte[] cipherText = cipher.doFinal(cmk);
    // byte[] cipherText = CryptoUtils.rsaoaepEncryptBytes(cmk, aRsaPublicKey);

    Cipher bcDecrypter = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", "SunJCE");
    bcDecrypter.init(Cipher.DECRYPT_MODE, aRsaPrivKey);
    byte[] decrypted = bcDecrypter.doFinal(cipherText);
    assertTrue(Arrays.equals(cmk, decrypted));

    Cipher sunDecrypter = Cipher.getInstance("RSA/None/OAEPWithSHA-1AndMGF1Padding", bc);
    sunDecrypter.init(Cipher.DECRYPT_MODE, aRsaPrivKey);
    decrypted = sunDecrypter.doFinal(cipherText);
    assertTrue(Arrays.equals(cmk, decrypted));
  }

  private void testAesGcm(IvParameterSpec ivParamSpec, SecretKey secretKey, byte[] plaintext)
      throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException,
      ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    byte[] ciphertext = CryptoUtils.aesgcmEncrypt(ivParamSpec, secretKey, plaintext);

    byte[] recoveredplaintext = CryptoUtils.aesgcmDecrypt(ivParamSpec, secretKey, ciphertext);

    String plaintextB64 = Base64.encodeBytesNoBreaks(plaintext);
    String recoveredplaintextB64 = Base64.encodeBytesNoBreaks(recoveredplaintext);
    assertEquals(plaintextB64, recoveredplaintextB64);
  }

  public void testAesGcm128() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
      InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    byte[] plaintext = "plaintext".getBytes();
    String keybytes128B64 = "wkp7v4KkBox9rSwVBXT+aA==";

    byte[] keyData = Base64.decode(keybytes128B64);
    SecretKey secretKey = new SecretKeySpec(keyData, "AES128");

    byte[] N = Hex.decode("cafebabefacedbaddecaf888");
    IvParameterSpec ivParamSpec = new IvParameterSpec(N);

    testAesGcm(ivParamSpec, secretKey, plaintext);
  }

  public void testAesGcm128Auth() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
      InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException,
      IllegalStateException, InvalidCipherTextException {

    // String plaintext = "Live long and prosper.";
    byte[] plaintextBytes = { 76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32, 112, 114, 111, 115, 112,
        101, 114, 46 };
    byte[] cmk = { (byte) 177, (byte) 161, (byte) 244, (byte) 128, (byte) 84, (byte) 143, (byte) 225, (byte) 115,
        (byte) 63, (byte) 180, (byte) 3, (byte) 255, (byte) 107, (byte) 154, (byte) 212, (byte) 246, (byte) 138,
        (byte) 7, (byte) 110, (byte) 91, (byte) 112, (byte) 46, (byte) 34, (byte) 105, (byte) 47, (byte) 130,
        (byte) 203, (byte) 46, (byte) 122, (byte) 234, (byte) 64, (byte) 252 };

    byte[] associatedText = { 101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69, 116, 84, 48, 70, 70, 85,
        67, 73, 115, 73, 109, 86, 117, 89, 121, 73, 54, 73, 107, 69, 121, 78, 84, 90, 72, 81, 48, 48, 105, 76, 67, 74,
        112, 100, 105, 73, 54, 73, 106, 81, 52, 86, 106, 70, 102, 81, 85, 120, 105, 78, 108, 86, 84, 77, 68, 82, 86,
        77, 50, 73, 105, 102, 81, 46, 106, 118, 119, 111, 121, 104, 87, 120, 79, 77, 98, 111, 66, 53, 99, 120, 88, 54,
        110, 99, 65, 105, 55, 87, 112, 51, 81, 53, 70, 75, 82, 116, 108, 109, 73, 120, 51, 53, 112, 102, 82, 57, 72,
        112, 69, 97, 54, 79, 121, 45, 105, 69, 112, 120, 69, 113, 77, 51, 48, 87, 51, 89, 99, 82, 81, 56, 87, 85, 57,
        111, 117, 82, 111, 79, 53, 106, 100, 54, 116, 102, 100, 99, 112, 88, 45, 50, 88, 45, 79, 116, 101, 72, 119, 52,
        100, 110, 77, 88, 100, 77, 76, 106, 72, 71, 71, 120, 56, 54, 76, 77, 68, 101, 70, 82, 65, 78, 50, 75, 71, 122,
        55, 69, 71, 80, 74, 105, 118, 97, 119, 48, 121, 77, 56, 48, 102, 122, 84, 51, 122, 89, 48, 80, 75, 114, 73,
        118, 85, 53, 109, 108, 49, 77, 53, 115, 122, 113, 85, 110, 88, 52, 74, 119, 48, 45, 80, 78, 99, 73, 77, 95,
        106, 45, 76, 53, 89, 107, 76, 104, 118, 51, 89, 107, 48, 52, 88, 67, 119, 84, 74, 119, 120, 78, 78, 109, 88,
        67, 102, 108, 89, 65, 81, 79, 57, 102, 48, 48, 65, 97, 50, 49, 51, 84, 74, 74, 114, 54, 100, 98, 72, 86, 54,
        73, 54, 52, 50, 70, 119, 85, 45, 69, 87, 118, 116, 69, 102, 78, 51, 101, 118, 103, 88, 51, 69, 70, 73, 86, 89,
        83, 110, 84, 51, 72, 67, 72, 107, 65, 65, 73, 100, 66, 81, 57, 121, 107, 68, 45, 97, 98, 82, 122, 86, 65, 95,
        100, 71, 112, 95, 121, 74, 65, 90, 81, 99, 114, 90, 117, 78, 84, 113, 122, 84, 104, 100, 95, 50, 50, 89, 77,
        80, 104, 73, 112, 122, 84, 121, 103, 102, 67, 95, 52, 107, 55, 113, 113, 120, 73, 54, 116, 55, 76, 101, 95,
        108, 53, 95, 111, 45, 116, 97, 85, 71, 55, 118, 97, 78, 65, 108, 53, 70, 106, 69, 81 };
    KeyParameter key = new KeyParameter(cmk);
    int macSizeBits = 128;
    int macSize = macSizeBits / 8;

    byte[] nonce = { (byte) 227, (byte) 197, (byte) 117, (byte) 252, (byte) 2, (byte) 219, (byte) 233, (byte) 68,
        (byte) 180, (byte) 225, (byte) 77, (byte) 219 };
    String ivB64 = "48V1_ALb6US04U3b";
    String nonceB64 = Base64.encodeBytes(nonce, org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
    assertEquals(ivB64, nonceB64);

    AEADParameters aeadParameters = new AEADParameters(key, macSizeBits, nonce, associatedText);

    byte[] out = new byte[1024];
    BlockCipher blockCipher = new AESEngine();
    CipherParameters params = new KeyParameter(cmk);
    blockCipher.init(true, params);
    GCMBlockCipher aGCMBlockCipher = new GCMBlockCipher(blockCipher);
    aGCMBlockCipher.init(true, aeadParameters);
    int outOff = aGCMBlockCipher.processBytes(plaintextBytes, 0, plaintextBytes.length, out, 0);
    outOff += aGCMBlockCipher.doFinal(out, outOff);
    assertEquals(38, outOff);
    byte[] cipherText = new byte[outOff - macSize];
    System.arraycopy(out, 0, cipherText, 0, cipherText.length);
    String cipherTextB64 = Base64.encodeBytes(cipherText, org.xmldap.util.Base64.DONT_BREAK_LINES
        | org.xmldap.util.Base64.URL);
    String expectedCipherTextB64 = "_e21tGGhac_peEFkLXr2dMPUZiUkrw";
    assertEquals(expectedCipherTextB64, cipherTextB64);
    byte[] auth = new byte[macSize];
    System.arraycopy(out, outOff - macSize, auth, 0, auth.length);
    String authB64 = Base64.encodeBytes(auth, org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
    String expectedAuthB64 = "YbZSeHCNDZBqAdzpROlyiw";
    assertEquals(expectedAuthB64, authB64);
  }

  public void testEncryptAesGcmAEAD() throws Exception {
    String encodedJwtHeader = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00iLCJpdiI6IjQ4VjFfQUxiNlVTMDRVM2IifQ";
    String encodedJweEncryptedKey = "jvwoyhWxOMboB5cxX6ncAi7Wp3Q5FKRtlmIx35pfR9HpEa6Oy-iEpxEqM30W3YcR"
        + "Q8WU9ouRoO5jd6tfdcpX-2X-OteHw4dnMXdMLjHGGx86LMDeFRAN2KGz7EGPJiva"
        + "w0yM80fzT3zY0PKrIvU5ml1M5szqUnX4Jw0-PNcIM_j-L5YkLhv3Yk04XCwTJwxN"
        + "NmXCflYAQO9f00Aa213TJJr6dbHV6I642FwU-EWvtEfN3evgX3EFIVYSnT3HCHkA"
        + "AIdBQ9ykD-abRzVA_dGp_yJAZQcrZuNTqzThd_22YMPhIpzTygfC_4k7qqxI6t7L" + "e_l5_o-taUG7vaNAl5FjEQ";

    byte[] cmk = { (byte) 177, (byte) 161, (byte) 244, (byte) 128, (byte) 84, (byte) 143, (byte) 225, (byte) 115,
        (byte) 63, (byte) 180, (byte) 3, (byte) 255, (byte) 107, (byte) 154, (byte) 212, (byte) 246, (byte) 138,
        (byte) 7, (byte) 110, (byte) 91, (byte) 112, (byte) 46, (byte) 34, (byte) 105, (byte) 47, (byte) 130,
        (byte) 203, (byte) 46, (byte) 122, (byte) 234, (byte) 64, (byte) 252 };
    byte[] plaintextBytes = { 76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32, 112, 114, 111, 115, 112,
        101, 114, 46 };
    KeyParameter key = new KeyParameter(cmk);
    int macSizeBits = 128;
    byte[] nonce = { (byte) 227, (byte) 197, (byte) 117, (byte) 252, (byte) 2, (byte) 219, (byte) 233, (byte) 68,
        (byte) 180, (byte) 225, (byte) 77, (byte) 219 };
    String associatedText = encodedJwtHeader.concat(".").concat(encodedJweEncryptedKey);
    String expected = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00iLCJpdiI6IjQ4VjFfQUxi" + "NlVTMDRVM2IifQ."
        + "jvwoyhWxOMboB5cxX6ncAi7Wp3Q5FKRtlmIx35pfR9HpEa6Oy-iEpxEqM30W3YcR"
        + "Q8WU9ouRoO5jd6tfdcpX-2X-OteHw4dnMXdMLjHGGx86LMDeFRAN2KGz7EGPJiva"
        + "w0yM80fzT3zY0PKrIvU5ml1M5szqUnX4Jw0-PNcIM_j-L5YkLhv3Yk04XCwTJwxN"
        + "NmXCflYAQO9f00Aa213TJJr6dbHV6I642FwU-EWvtEfN3evgX3EFIVYSnT3HCHkA"
        + "AIdBQ9ykD-abRzVA_dGp_yJAZQcrZuNTqzThd_22YMPhIpzTygfC_4k7qqxI6t7L" + "e_l5_o-taUG7vaNAl5FjEQ";
    assertEquals(expected, associatedText);
    byte[] associatedTextBytes = associatedText.getBytes();
    AEADParameters aeadParameters = new AEADParameters(key, macSizeBits, nonce, associatedTextBytes);

    SecretKey keySpec = new SecretKeySpec(cmk, "AES");
    String[] result = CryptoUtils.aesgcmEncrypt(aeadParameters, keySpec, plaintextBytes);
    String encodedJweCiphertext = result[0];
    String encodedJweIntegrityValue = result[1];
    assertEquals("_e21tGGhac_peEFkLXr2dMPUZiUkrw", encodedJweCiphertext);
    assertEquals("YbZSeHCNDZBqAdzpROlyiw", encodedJweIntegrityValue);
  }
  
  public void testAesCbc() throws Exception {
    
  }
}
