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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.ECUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.json.JSONException;
import org.json.JSONObject;
import org.xmldap.exceptions.CryptoException;
import org.xmldap.util.Base64;

public class WebTokenTest extends TestCase {
  JSONObject joeO = null;

  String joeStr = "{\"iss\":\"joe\",\r\n" + " \"exp\":1300819380,\r\n" + " \"http://example.com/is_root\":true}";

  String hs256 = "{\"typ\":\"JWT\",\r\n" + " \"alg\":\"HS256\"}";
  String hs384 = "{\"typ\":\"JWT\",\r\n" + " \"alg\":\"HS384\"}";
  String hs512 = "{\"typ\":\"JWT\",\r\n" + " \"alg\":\"HS512\"}";
  byte[] hsKey = { 3, (byte) 35, (byte) 53, (byte) 75, (byte) 43, (byte) 15, (byte) 165, (byte) 188, (byte) 131,
      (byte) 126, (byte) 6, (byte) 101, (byte) 119, (byte) 123, (byte) 166, (byte) 143, (byte) 90, (byte) 179,
      (byte) 40, (byte) 230, (byte) 240, (byte) 84, (byte) 201, (byte) 40, (byte) 169, (byte) 15, (byte) 132,
      (byte) 178, (byte) 210, (byte) 80, (byte) 46, (byte) 191, (byte) 211, (byte) 251, (byte) 90, (byte) 146,
      (byte) 210, (byte) 6, (byte) 71, (byte) 239, (byte) 150, (byte) 138, (byte) 180, (byte) 195, (byte) 119,
      (byte) 98, (byte) 61, (byte) 34, (byte) 61, (byte) 46, (byte) 33, (byte) 114, (byte) 5, (byte) 46, (byte) 79,
      (byte) 8, (byte) 192, (byte) 205, (byte) 154, (byte) 245, (byte) 103, (byte) 208, (byte) 128, (byte) 163 };

  String es256 = "{\"alg\":\"ES256\"}";
  String es384 = "{\"alg\":\"ES384\"}";
  String es512 = "{\"alg\":\"ES512\"}";

  String rs256 = "{\"alg\":\"RS256\"}";
  String rs384 = "{\"alg\":\"RS384\"}";
  String rs512 = "{\"alg\":\"RS512\"}";

  String ae128 = "{\"alg\":\"AE128\"}";
  String ae192 = "{\"alg\":\"AE192\"}";
  String ae256 = "{\"alg\":\"AE256\"}";

  String A128GCM = "{\"alg\":\"A128GCM\"}";

  String re256GCM = "{\"alg\":\"RSA1_5\",\r\n" + "\"enc\":\"A256GCM\",\r\n" + "\"iv\":\"__79_Pv6-fg\",\r\n"
      + "\"x5t\":\"7noOPq-hJ1_hCnvWh6IeYI2w9Q0\"}";

  String re128GCM = "{\"alg\":\"RSA1_5\",\r\n" + "\"enc\":\"A128GCM\",\r\n" + "\"iv\":\"__79_Pv6-fg\",\r\n"
      + "\"x5t\":\"7noOPq-hJ1_hCnvWh6IeYI2w9Q0\"}";

  String ae128b64;
  String ae192b64;
  String ae256b64;

  String rsa15AesGcm128HeaderStr;
  String rsa15AesGcm128HeaderStrb64;

  String rsa15AesGcm256HeaderStr;
  String rsa15AesGcm256HeaderStrb64;

  String rsaOaepAesCbc128HeaderStr;
  String rsaOaepAesCbc128HeaderStrb64;

  String rsaOaepAesCbc192HeaderStr;
  String rsaOaepAesCbc192HeaderStrb64;

  String rsaOaepAesCbc256HeaderStr;
  String rsaOaepAesCbc256HeaderStrb64;

  RSAPublicKey rsaPublicKey;
  RSAPrivateKey rsaPrivKey;

  static final byte[] ec256_1_x = { 48, (byte) 160, 66, 76, (byte) 210, 28, 41, 68, (byte) 131, (byte) 138, 45, 117,
      (byte) 201, 43, 55, (byte) 231, 110, (byte) 162, 13, (byte) 159, 0, (byte) 137, 58, 59, 78, (byte) 238,
      (byte) 138, 60, 10, (byte) 175, (byte) 236, 62 };
  static final byte[] ec256_1_y = { (byte) 224, 75, 101, (byte) 233, 36, 86, (byte) 217, (byte) 136, (byte) 139, 82,
      (byte) 179, 121, (byte) 189, (byte) 251, (byte) 213, 30, (byte) 232, 105, (byte) 239, 31, 15, (byte) 198, 91,
      102, 89, 105, 91, 108, (byte) 206, 8, 23, 35 };
  static final byte[] ec256_1_d = { (byte) 243, (byte) 189, 12, 7, (byte) 168, 31, (byte) 185, 50, 120, 30, (byte) 213,
      39, 82, (byte) 246, 12, (byte) 200, (byte) 154, 107, (byte) 229, (byte) 229, 25, 52, (byte) 254, 1, (byte) 147,
      (byte) 141, (byte) 219, 85, (byte) 216, (byte) 247, 120, 1 };

  static final String ec256_a_priv = "072f2322c0e75e0c851764b42181996778fd22592f87e5d43836097429a1c3fc";
  // static final String ec256_a_pub =
  // "04ed3c831bf3e1059f12077f4be4fdfe905573d1c67645b47d4864ea179dde9986a9a6ad34274a80fc94b3a5ef6c6e782c227a3963a6a42650976da6ade990a161";
  static final String ec256_b_priv = "1a3eda89dc067871530601f934c6428574f837507c578e45bd10a29b2e019bfb";
  // static final String ec256_b_pub =
  // "049d887ec41f36201c1868f1c09c9a93cb9d5a0ff9d08af8dde2175b25ffaa834a6caadaba025a4477beb53af076bdab597153666c70d8458c49df24713ee55e85";

  BigInteger ec256_a_D;
  BigInteger ec256_a_X;
  BigInteger ec256_a_Y;
  String ec256_a_header;
  BigInteger ec256_b_D;
  BigInteger ec256_b_X;
  BigInteger ec256_b_Y;
  String ec256_b_header;

  String ee256;

  String keybytes128B64 = null;
  String keybytes256B64 = null;

  AsymmetricCipherKeyPair eckp = null;

  public void setUp() {
    try {
      super.setUp();

      final byte[] n = { (byte) 161, (byte) 248, (byte) 22, (byte) 10, (byte) 226, (byte) 227, (byte) 201, (byte) 180,
          (byte) 101, (byte) 206, (byte) 141, (byte) 45, (byte) 101, (byte) 98, (byte) 99, (byte) 54, (byte) 43,
          (byte) 146, (byte) 125, (byte) 190, (byte) 41, (byte) 225, (byte) 240, (byte) 36, (byte) 119, (byte) 252,
          (byte) 22, (byte) 37, (byte) 204, (byte) 144, (byte) 161, (byte) 54, (byte) 227, (byte) 139, (byte) 217,
          (byte) 52, (byte) 151, (byte) 197, (byte) 182, (byte) 234, (byte) 99, (byte) 221, (byte) 119, (byte) 17,
          (byte) 230, (byte) 124, (byte) 116, (byte) 41, (byte) 249, (byte) 86, (byte) 176, (byte) 251, (byte) 138,
          (byte) 143, (byte) 8, (byte) 154, (byte) 220, (byte) 75, (byte) 105, (byte) 137, (byte) 60, (byte) 193,
          (byte) 51, (byte) 63, (byte) 83, (byte) 237, (byte) 208, (byte) 25, (byte) 184, (byte) 119, (byte) 132,
          (byte) 37, (byte) 47, (byte) 236, (byte) 145, (byte) 79, (byte) 228, (byte) 133, (byte) 119, (byte) 105,
          (byte) 89, (byte) 75, (byte) 234, (byte) 66, (byte) 128, (byte) 211, (byte) 44, (byte) 15, (byte) 85,
          (byte) 191, (byte) 98, (byte) 148, (byte) 79, (byte) 19, (byte) 3, (byte) 150, (byte) 188, (byte) 110,
          (byte) 155, (byte) 223, (byte) 110, (byte) 189, (byte) 210, (byte) 189, (byte) 163, (byte) 103, (byte) 142,
          (byte) 236, (byte) 160, (byte) 198, (byte) 104, (byte) 247, (byte) 1, (byte) 179, (byte) 141, (byte) 191,
          (byte) 251, (byte) 56, (byte) 200, (byte) 52, (byte) 44, (byte) 226, (byte) 254, (byte) 109, (byte) 39,
          (byte) 250, (byte) 222, (byte) 74, (byte) 90, (byte) 72, (byte) 116, (byte) 151, (byte) 157, (byte) 212,
          (byte) 185, (byte) 207, (byte) 154, (byte) 222, (byte) 196, (byte) 199, (byte) 91, (byte) 5, (byte) 133,
          (byte) 44, (byte) 44, (byte) 15, (byte) 94, (byte) 248, (byte) 165, (byte) 193, (byte) 117, (byte) 3,
          (byte) 146, (byte) 249, (byte) 68, (byte) 232, (byte) 237, (byte) 100, (byte) 193, (byte) 16, (byte) 198,
          (byte) 182, (byte) 71, (byte) 96, (byte) 154, (byte) 164, (byte) 120, (byte) 58, (byte) 235, (byte) 156,
          (byte) 108, (byte) 154, (byte) 215, (byte) 85, (byte) 49, (byte) 48, (byte) 80, (byte) 99, (byte) 139,
          (byte) 131, (byte) 102, (byte) 92, (byte) 111, (byte) 111, (byte) 122, (byte) 130, (byte) 163, (byte) 150,
          (byte) 112, (byte) 42, (byte) 31, (byte) 100, (byte) 27, (byte) 130, (byte) 211, (byte) 235, (byte) 242,
          (byte) 57, (byte) 34, (byte) 25, (byte) 73, (byte) 31, (byte) 182, (byte) 134, (byte) 135, (byte) 44,
          (byte) 87, (byte) 22, (byte) 245, (byte) 10, (byte) 248, (byte) 53, (byte) 141, (byte) 154, (byte) 139,
          (byte) 157, (byte) 23, (byte) 195, (byte) 64, (byte) 114, (byte) 143, (byte) 127, (byte) 135, (byte) 216,
          (byte) 154, (byte) 24, (byte) 216, (byte) 252, (byte) 171, (byte) 103, (byte) 173, (byte) 132, (byte) 89,
          (byte) 12, (byte) 46, (byte) 207, (byte) 117, (byte) 147, (byte) 57, (byte) 54, (byte) 60, (byte) 7,
          (byte) 3, (byte) 77, (byte) 111, (byte) 96, (byte) 111, (byte) 158, (byte) 33, (byte) 224, (byte) 84,
          (byte) 86, (byte) 202, (byte) 229, (byte) 233, (byte) 161 };
      final byte[] e = { 1, 0, 1 };
      final byte[] d = { 18, (byte) 174, (byte) 113, (byte) 164, (byte) 105, (byte) 205, (byte) 10, (byte) 43,
          (byte) 195, (byte) 126, (byte) 82, (byte) 108, (byte) 69, (byte) 0, (byte) 87, (byte) 31, (byte) 29,
          (byte) 97, (byte) 117, (byte) 29, (byte) 100, (byte) 233, (byte) 73, (byte) 112, (byte) 123, (byte) 98,
          (byte) 89, (byte) 15, (byte) 157, (byte) 11, (byte) 165, (byte) 124, (byte) 150, (byte) 60, (byte) 64,
          (byte) 30, (byte) 63, (byte) 207, (byte) 47, (byte) 44, (byte) 211, (byte) 189, (byte) 236, (byte) 136,
          (byte) 229, (byte) 3, (byte) 191, (byte) 198, (byte) 67, (byte) 155, (byte) 11, (byte) 40, (byte) 200,
          (byte) 47, (byte) 125, (byte) 55, (byte) 151, (byte) 103, (byte) 31, (byte) 82, (byte) 19, (byte) 238,
          (byte) 216, (byte) 193, (byte) 90, (byte) 37, (byte) 216, (byte) 213, (byte) 206, (byte) 160, (byte) 2,
          (byte) 94, (byte) 227, (byte) 171, (byte) 46, (byte) 139, (byte) 127, (byte) 121, (byte) 33, (byte) 111,
          (byte) 198, (byte) 59, (byte) 234, (byte) 86, (byte) 39, (byte) 83, (byte) 180, (byte) 6, (byte) 68,
          (byte) 198, (byte) 161, (byte) 81, (byte) 39, (byte) 217, (byte) 178, (byte) 149, (byte) 69, (byte) 64,
          (byte) 160, (byte) 187, (byte) 225, (byte) 163, (byte) 5, (byte) 86, (byte) 152, (byte) 45, (byte) 78,
          (byte) 159, (byte) 222, (byte) 95, (byte) 100, (byte) 37, (byte) 241, (byte) 77, (byte) 75, (byte) 113,
          (byte) 52, (byte) 65, (byte) 181, (byte) 93, (byte) 199, (byte) 59, (byte) 155, (byte) 74, (byte) 237,
          (byte) 204, (byte) 146, (byte) 172, (byte) 227, (byte) 146, (byte) 126, (byte) 55, (byte) 245, (byte) 125,
          (byte) 12, (byte) 253, (byte) 94, (byte) 117, (byte) 129, (byte) 250, (byte) 81, (byte) 44, (byte) 143,
          (byte) 73, (byte) 97, (byte) 169, (byte) 235, (byte) 11, (byte) 128, (byte) 248, (byte) 168, (byte) 7,
          (byte) 70, (byte) 114, (byte) 138, (byte) 85, (byte) 255, (byte) 70, (byte) 71, (byte) 31, (byte) 52,
          (byte) 37, (byte) 6, (byte) 59, (byte) 157, (byte) 83, (byte) 100, (byte) 47, (byte) 94, (byte) 222,
          (byte) 30, (byte) 132, (byte) 214, (byte) 19, (byte) 8, (byte) 26, (byte) 250, (byte) 92, (byte) 34,
          (byte) 208, (byte) 81, (byte) 40, (byte) 91, (byte) 214, (byte) 59, (byte) 148, (byte) 59, (byte) 86,
          (byte) 93, (byte) 137, (byte) 138, (byte) 5, (byte) 104, (byte) 84, (byte) 19, (byte) 229, (byte) 60,
          (byte) 60, (byte) 108, (byte) 101, (byte) 37, (byte) 255, (byte) 31, (byte) 227, (byte) 78, (byte) 61,
          (byte) 220, (byte) 112, (byte) 240, (byte) 213, (byte) 100, (byte) 80, (byte) 253, (byte) 164, (byte) 139,
          (byte) 161, (byte) 46, (byte) 16, (byte) 78, (byte) 157, (byte) 235, (byte) 159, (byte) 184, (byte) 24,
          (byte) 129, (byte) 225, (byte) 196, (byte) 189, (byte) 242, (byte) 93, (byte) 146, (byte) 71, (byte) 244,
          (byte) 80, (byte) 200, (byte) 101, (byte) 146, (byte) 121, (byte) 104, (byte) 231, (byte) 115, (byte) 52,
          (byte) 244, (byte) 65, (byte) 79, (byte) 117, (byte) 167, (byte) 80, (byte) 225, (byte) 57, (byte) 84,
          (byte) 110, (byte) 58, (byte) 138, (byte) 115, (byte) 157 };

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
      /* int result = */digest.doFinal(out, 0);
      String thumbprint = Base64.encodeBytes(out, org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);

      rsa15AesGcm128HeaderStr = "{\"alg\":\"" + WebToken.ENC_ALG_RSA1_5 + "\",\r\n" + " \"enc\":\""
          + WebToken.ENC_ALG_A128GCM + "\",\r\n" + " \"x5t\":\"" + thumbprint + "\"}";
      rsa15AesGcm128HeaderStrb64 = Base64.encodeBytes(rsa15AesGcm128HeaderStr.getBytes("utf-8"),
          org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);

      rsa15AesGcm256HeaderStr = "{\"alg\":\"" + WebToken.ENC_ALG_RSA1_5 + "\",\r\n" + " \"enc\":\""
          + WebToken.ENC_ALG_A256GCM + "\",\r\n" + " \"x5t\":\"" + thumbprint + "\"}";
      rsa15AesGcm256HeaderStrb64 = Base64.encodeBytes(rsa15AesGcm256HeaderStr.getBytes("utf-8"),
          org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);

      rsaOaepAesCbc128HeaderStr = "{\"alg\":\"" + WebToken.ENC_ALG_RSA_OAEP + "\",\r\n" + " \"enc\":\""
          + WebToken.ENC_ALG_A128CBC + "\",\r\n" + " \"int\":\"" + WebToken.SIGN_ALG_HS256 + "\",\r\n" + " \"x5t\":\""
          + thumbprint + "\"}";
      rsaOaepAesCbc128HeaderStrb64 = Base64.encodeBytes(rsaOaepAesCbc128HeaderStr.getBytes("utf-8"),
          org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);

      rsaOaepAesCbc192HeaderStr = "{\"alg\":\"" + WebToken.ENC_ALG_RSA_OAEP + "\",\r\n" + " \"enc\":\""
          + WebToken.ENC_ALG_A192CBC + "\",\r\n" + " \"int\":\"" + WebToken.SIGN_ALG_HS256 + "\",\r\n" + " \"x5t\":\""
          + thumbprint + "\"}";
      rsaOaepAesCbc192HeaderStrb64 = Base64.encodeBytes(rsaOaepAesCbc192HeaderStr.getBytes("utf-8"),
          org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);

      rsaOaepAesCbc256HeaderStr = "{\"alg\":\"" + WebToken.ENC_ALG_RSA_OAEP + "\",\r\n" + " \"enc\":\""
          + WebToken.ENC_ALG_A256CBC + "\",\r\n" + " \"int\":\"" + WebToken.SIGN_ALG_HS256 + "\",\r\n" + " \"x5t\":\""
          + thumbprint + "\"}";
      rsaOaepAesCbc256HeaderStrb64 = Base64.encodeBytes(rsaOaepAesCbc256HeaderStr.getBytes("utf-8"),
          org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);

      ae128b64 = Base64.encodeBytes(ae128.getBytes("utf-8"), org.xmldap.util.Base64.DONT_BREAK_LINES
          | org.xmldap.util.Base64.URL);
      ae192b64 = Base64.encodeBytes(ae192.getBytes("utf-8"), org.xmldap.util.Base64.DONT_BREAK_LINES
          | org.xmldap.util.Base64.URL);
      ae256b64 = Base64.encodeBytes(ae256.getBytes("utf-8"), org.xmldap.util.Base64.DONT_BREAK_LINES
          | org.xmldap.util.Base64.URL);

      // byte[] keybytes128 = new byte[16];
      // SecureRandom random = new SecureRandom();
      // random.nextBytes(keybytes128);
      // keybytes128B64 = Base64.encodeBytesNoBreaks(keybytes128);
      // System.out.println("keybytes128B64=" + keybytes128B64);
      //
      // byte[] keybytes256 = new byte[32];
      // random.nextBytes(keybytes256);
      // keybytes256B64 = Base64.encodeBytesNoBreaks(keybytes256);
      // System.out.println("keybytes256B64=" + keybytes256B64);

      keybytes128B64 = "wkp7v4KkBox9rSwVBXT+aA==";
      keybytes256B64 = "aRjpB3nhFA7B7B+sKwfM4OhU+6kLeg0W7p6OFbn7AfE=";

      String ec256_1_x_b64 = Base64.encodeBytes(ec256_1_x, org.xmldap.util.Base64.DONT_BREAK_LINES
          | org.xmldap.util.Base64.URL);
      String ec256_1_y_b64 = Base64.encodeBytes(ec256_1_y, org.xmldap.util.Base64.DONT_BREAK_LINES
          | org.xmldap.util.Base64.URL);
      ee256 = "{\"alg\":\"ECDH-ES\",\r\n" + "\"enc\":\"" + WebToken.ENC_ALG_A256GCM + "\",\r\n"
          + "\"iv\":\"__79_Pv6-fg\",\r\n" + "\"crv\":\"secp256r1\",\r\n" + "\"x\":\"" + ec256_1_x_b64 + "\",\r\n"
          + "\"y\":\"" + ec256_1_y_b64 + "\"}";

      ASN1ObjectIdentifier oid = ECUtil.getNamedCurveOid("secp256r1");
      X9ECParameters x9ECParameters = ECUtil.getNamedCurveByOid(oid);
      // ECCurve curve = x9ECParameters.getCurve();

      {
        byte[] ec256_a_priv_bytes = Hex.decode(ec256_a_priv);
        ec256_a_D = new BigInteger(1, ec256_a_priv_bytes);
        ECPoint pub = x9ECParameters.getG().multiply(ec256_a_D);
        ec256_a_X = pub.getX().toBigInteger();
        ec256_a_Y = pub.getY().toBigInteger();
        // byte[] xyBytes = Hex.decode(ec256_a_pub);
        // byte[] xBytes = new byte[xyBytes.length/2];
        // System.arraycopy(xyBytes, 0, xBytes, 0, xBytes.length);
        // ec256_a_X = new BigInteger(1, xBytes);
        // String ec256_a_X_b64 = Base64.encodeBytes(xBytes,
        // org.xmldap.util.Base64.DONT_BREAK_LINES |
        // org.xmldap.util.Base64.URL);
        String ec256_a_X_b64 = Base64.encodeBytes(ec256_a_X.toByteArray(), org.xmldap.util.Base64.DONT_BREAK_LINES
            | org.xmldap.util.Base64.URL);
        // byte[] yBytes = new byte[xyBytes.length/2];
        // System.arraycopy(xyBytes, xBytes.length/2, yBytes, 0, yBytes.length);
        // ec256_a_Y = new BigInteger(1, yBytes);
        // String ec256_a_Y_b64 = Base64.encodeBytes(yBytes,
        // org.xmldap.util.Base64.DONT_BREAK_LINES |
        // org.xmldap.util.Base64.URL);
        String ec256_a_Y_b64 = Base64.encodeBytes(ec256_a_Y.toByteArray(), org.xmldap.util.Base64.DONT_BREAK_LINES
            | org.xmldap.util.Base64.URL);
        ec256_a_header = "{\"alg\":\"ECDH-ES\",\r\n" + "\"enc\":\"" + WebToken.ENC_ALG_A256GCM + "\",\r\n"
            + "\"iv\":\"__79_Pv6-fg\",\r\n" + "\"epk\": {\"jwk\": [{\r\n" + " \"crv\":\"secp256r1\",\r\n" + " \"x\":\""
            + ec256_a_X_b64 + "\",\r\n" + " \"y\":\"" + ec256_a_Y_b64 + "\"}]}}";
      }
      {
        byte[] ec256_b_priv_bytes = Hex.decode(ec256_b_priv);
        ec256_b_D = new BigInteger(1, ec256_b_priv_bytes);
        ECPoint pub = x9ECParameters.getG().multiply(ec256_b_D);
        ec256_b_X = pub.getX().toBigInteger();
        ec256_b_Y = pub.getY().toBigInteger();
        // byte[] xyBytes = Hex.decode(ec256_b_pub);
        // byte[] xBytes = new byte[xyBytes.length/2];
        // System.arraycopy(xyBytes, 0, xBytes, 0, xBytes.length);
        // ec256_b_X = new BigInteger(1, xBytes);
        String ec256_b_X_b64 = Base64.encodeBytes(ec256_b_X.toByteArray(), org.xmldap.util.Base64.DONT_BREAK_LINES
            | org.xmldap.util.Base64.URL);
        // String ec256_b_X_b64 = Base64.encodeBytes(xBytes,
        // org.xmldap.util.Base64.DONT_BREAK_LINES |
        // org.xmldap.util.Base64.URL);
        // byte[] yBytes = new byte[xyBytes.length/2];
        // System.arraycopy(xyBytes, xBytes.length/2, yBytes, 0, yBytes.length);
        // ec256_b_Y = new BigInteger(1, yBytes);
        // String ec256_b_Y_b64 = Base64.encodeBytes(yBytes,
        // org.xmldap.util.Base64.DONT_BREAK_LINES |
        // org.xmldap.util.Base64.URL);
        String ec256_b_Y_b64 = Base64.encodeBytes(ec256_b_Y.toByteArray(), org.xmldap.util.Base64.DONT_BREAK_LINES
            | org.xmldap.util.Base64.URL);
        ec256_b_header = "{\"alg\":\"ECDH-ES\",\r\n" + "\"enc\":\"" + WebToken.ENC_ALG_A256GCM + "\",\r\n"
            + "\"iv\":\"--68-Ou5_ef\",\r\n" + "\"epk\": {\"jwk\": [{\r\n" + " \"crv\":\"secp256r1\",\r\n" + " \"x\":\""
            + ec256_b_X_b64 + "\",\r\n" + " \"y\":\"" + ec256_b_Y_b64 + "\"}]}}";

      }
    } catch (Exception e) {
      assertTrue(false);
    }
  }

  public void testBadHeader() throws Exception {
    String b = "{\"alg\":\"ECDH-ES\",\"alg\":\"another alg\"}";
    try {
      JSONObject j = new JSONObject(b);
      fail();
    } catch (JSONException e) {

    }
  }

  // public void testAesGcm256() throws InvalidKeyException,
  // NoSuchAlgorithmException, NoSuchPaddingException,
  // InvalidAlgorithmParameterException, ShortBufferException,
  // IllegalBlockSizeException, BadPaddingException
  // {
  // byte[] plaintext = "plaintext".getBytes();
  // byte[] keyData = Base64.decode(keybytes256B64);
  // System.out.println("keyData.length=" + keyData.length);
  // byte[] N = Hex.decode("cafebabefacedbaddecaf888");
  // IvParameterSpec ivParamSpec = new IvParameterSpec(N);
  //
  // SecretKey secretKey = new SecretKeySpec(keyData , "AES256");
  // testAesGcm(ivParamSpec, secretKey, plaintext);
  // }

  public void testAesGcmJWE() throws Exception {
    JSONObject jweHeaderO = new JSONObject();
    jweHeaderO.put("alg", "A128GCM");
    byte[] ivBytes = Hex.decode("cafebabefacedbaddecaf888");
    String base64urlStr = Base64.encodeBytes(ivBytes, org.xmldap.util.Base64.DONT_BREAK_LINES
        | org.xmldap.util.Base64.URL);
    jweHeaderO.put("iv", base64urlStr);
    String jwe = jweHeaderO.toString();
    System.out.println("testAesGcmJWE jweB64url=" + jwe);
    WebToken jwt = new WebToken(joeStr, jweHeaderO);

    byte[] keyData = Base64.decode(keybytes128B64);
    System.out.println("keyData.length=" + keyData.length);
    byte[] N = Hex.decode("cafebabefacedbaddecaf888");
    IvParameterSpec ivParamSpec = new IvParameterSpec(N);
    SecretKey secretKey = new SecretKeySpec(keyData, "AES");

    String encryptedJWT = jwt.encrypt(secretKey, ivParamSpec);
    String expected = "eyJhbGciOiJBMTI4R0NNIiwiaXYiOiJ5djY2dnZyTzI2M2V5dmlJIn0.H7I-QNvM8VtMylQfBbbqyrT8xiFcVv-7CZTn-dkXr10dpIOmzjMbqjmbqevK2aAoRu4s5DhU8dbeu8SbRJTCDYYAkYfOo_Hc5NY6B5-VwhnOWc0sres";
    assertEquals(expected, encryptedJWT);

    String decryptedJWT = WebToken.decrypt(encryptedJWT, secretKey);
    assertEquals(joeStr, decryptedJWT);
  }

  public void testJoeEncoding() throws UnsupportedEncodingException {
    byte[] bytes = joeStr.getBytes("utf-8");
    String base64urlStr = Base64.encodeBytes(bytes, org.xmldap.util.Base64.DONT_BREAK_LINES
        | org.xmldap.util.Base64.URL);
    String expected = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
    assertEquals(expected, base64urlStr);
  }

  public void testHS256Encoding() throws UnsupportedEncodingException {
    byte[] bytes = hs256.getBytes("utf-8");
    String base64urlStr = Base64.encodeBytes(bytes, org.xmldap.util.Base64.DONT_BREAK_LINES
        | org.xmldap.util.Base64.URL);
    String expected = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";
    assertEquals(expected, base64urlStr);
  }

  public void testES256Encoding() throws UnsupportedEncodingException {
    byte[] bytes = es256.getBytes("utf-8");
    String base64urlStr = Base64.encodeBytes(bytes, org.xmldap.util.Base64.DONT_BREAK_LINES
        | org.xmldap.util.Base64.URL);
    String expected = "eyJhbGciOiJFUzI1NiJ9";
    assertEquals(expected, base64urlStr);
  }

  // public void testProviders() {
  // Security.addProvider(new BouncyCastleProvider());
  // Provider[] providers = java.security.Security.getProviders();
  // for (int i=0; i<providers.length; i++) {
  // Provider p = providers[i];
  // System.out.println(p.getName());
  // }
  // }

  public void testEDSAsignature_Draft01() throws Exception {
    String signature = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
    byte[] x = { 127, (byte) 205, (byte) 206, (byte) 39, (byte) 112, (byte) 246, (byte) 196, (byte) 93, (byte) 65,
        (byte) 131, (byte) 203, (byte) 238, (byte) 111, (byte) 219, (byte) 75, (byte) 123, (byte) 88, (byte) 7,
        (byte) 51, (byte) 53, (byte) 123, (byte) 233, (byte) 239, (byte) 19, (byte) 186, (byte) 207, (byte) 110,
        (byte) 60, (byte) 123, (byte) 209, (byte) 84, (byte) 69 };
    byte[] y = { (byte) 199, (byte) 241, (byte) 68, (byte) 205, (byte) 27, (byte) 189, (byte) 155, (byte) 126,
        (byte) 135, (byte) 44, (byte) 223, (byte) 237, (byte) 185, (byte) 238, (byte) 185, (byte) 244, (byte) 179,
        (byte) 105, (byte) 93, (byte) 110, (byte) 169, (byte) 11, (byte) 36, (byte) 173, (byte) 138, (byte) 70,
        (byte) 35, (byte) 40, (byte) 133, (byte) 136, (byte) 229, (byte) 173 };

    assertTrue(WebToken.verify(signature, x, y));
  }

  public void testEDSAsignature() throws Exception {
    // byte[] x = {48, (byte)160, 66, 76, (byte)210, 28, 41, 68, (byte)131,
    // (byte)138, 45, 117, (byte)201, 43, 55, (byte)231, 110, (byte)162, 13,
    // (byte)159, 0, (byte)137, 58, 59, 78, (byte)238, (byte)138, 60, 10,
    // (byte)175, (byte)236, 62};
    // byte[] y = {(byte)224, 75, 101, (byte)233, 36, 86, (byte)217, (byte)136,
    // (byte)139, 82, (byte)179, 121, (byte)189, (byte)251, (byte)213, 30,
    // (byte)232, 105, (byte)239, 31, 15, (byte)198, 91, 102, 89, 105, 91, 108,
    // (byte)206, 8, 23, 35};

    // "secp256r1 [NIST P-256, X9.62 prime256v1]", "1.2.840.10045.3.1.7"
    WebToken wt = new WebToken(joeStr, es256);
    String signed = wt.serialize(new BigInteger(1, ec256_1_d));
    String[] split = signed.split("\\.");
    assertEquals(3, split.length);
    assertEquals("eyJhbGciOiJFUzI1NiJ9", split[0]);
    assertEquals("eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
        split[1]);
    byte[] signatureBytes = Base64.decodeUrl(split[2]);
    assertEquals(64, signatureBytes.length);
    assertTrue(WebToken.verify(signed, ec256_1_x, ec256_1_y));

  }

  private void testHMACSHA(String jwtAlgorithm, String jwtHeaderSegment, String jwtCryptoSegment)
      throws InvalidKeyException, NoSuchAlgorithmException, IllegalStateException, UnsupportedEncodingException,
      JSONException {
    WebToken jwt = new WebToken(joeStr, jwtAlgorithm);
    String signed = jwt.serialize(hsKey);
    String[] split = signed.split("\\.");
    assertEquals(3, split.length);
    assertEquals(jwtHeaderSegment, split[0]);
    assertEquals("eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
        split[1]);
    assertEquals(jwtCryptoSegment, split[2]);
    String expected = split[0] + "." + split[1] + "." + split[2];
    assertEquals(expected, signed);
  }

  public void testHS256() throws InvalidKeyException, NoSuchAlgorithmException, IllegalStateException,
      UnsupportedEncodingException, JSONException {
    testHMACSHA(hs256, "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
  }

  public void testHS384() throws InvalidKeyException, NoSuchAlgorithmException, IllegalStateException,
      UnsupportedEncodingException, JSONException {
    testHMACSHA(hs384, "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzM4NCJ9",
        "TUfcA4Xjq_veopvw1fiFG99UswFSMvxYisxxBb0kHQ7w8He3OkvmELPo0uy3RuR0");
  }

  public void testHS512() throws InvalidKeyException, NoSuchAlgorithmException, IllegalStateException,
      UnsupportedEncodingException, JSONException {
    testHMACSHA(hs512, "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzUxMiJ9",
        "iXxB-yPnHRvriuSAfTrwz-gr5WYC6tg7gIq9JndRI9Uqn4D6twBgsJuQsQks6WqAC6OB23Lvdht79p_lA6jE8g");
  }

  private void testRSASHA(String jwtAlgorithm, String jwtHeaderSegment, String jwtCryptoSegment)
      throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException, JSONException,
      IOException {
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

  public void testRS256() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException,
      SignatureException, JSONException, IOException {
    String jwtHeaderSegment = "eyJhbGciOiJSUzI1NiJ9";
    String jwtCryptoSegment = "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";
    testRSASHA(rs256, jwtHeaderSegment, jwtCryptoSegment);
  }

  public void testRS384() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException,
      SignatureException, JSONException, IOException {
    String jwtHeaderSegment = "eyJhbGciOiJSUzM4NCJ9";
    String jwtCryptoSegment = "UqgNjrJOGhk4wfoSG6Uvrt9GcKu-TgPwInExALrMBadg1pol1uTw7mZADTddAWsC6ZzdFiTFUmIi7DuD38ftLAZoW4qezdAO7RYf1yZDsbT20bt8DJJN1I4VovL2PLg80B6x6ug-kaW8k5LaM5ce0dk1zgWhjafKC3Mb4UNLL8f9fqVMkHpdWYRjF6QjTz12Ap-gq-tPyUoWSdvzCIYOcZ9-08SQQdUTTgsNF1Qwu3TqeWPqzNJwmWHiHMmaV8I4ktMFEX-AiEBa55KsfYTx0jSbTHP-odqmnLQJ4n-oQJ2RSXy0HQP6BkdiwDHdoMUk4z_wAeOsfDTs_mLxTgOInQ";
    testRSASHA(rs384, jwtHeaderSegment, jwtCryptoSegment);
  }

  void testRsa(String name, String jwtHeaderSegment, String jwtHeaderSegmentB64) throws Exception {
    System.out.println("jwtHeaderSegment: " + name + " " + jwtHeaderSegment);
    System.out.println("jwtHeaderSegment: " + name + " " + jwtHeaderSegmentB64);

    WebToken jwt = new WebToken(joeStr, jwtHeaderSegment);
    String encrypted = jwt.encrypt(rsaPublicKey);

    String[] split = encrypted.split("\\.");

    assertEquals(4, split.length);

    String newJwtHeaderSegment = new String(Base64.decodeUrl(split[0]));
    JSONObject newJwtHeader = new JSONObject(newJwtHeaderSegment);
    JSONObject oldJwtHeader = new JSONObject(jwtHeaderSegment);

    assertEquals(oldJwtHeader.get("alg"), newJwtHeader.get("alg"));
    assertEquals(oldJwtHeader.get("enc"), newJwtHeader.get("enc"));
    String ivB64 = oldJwtHeader.optString("iv", null);
    if (ivB64 != null) {
      assertEquals(ivB64, newJwtHeader.get("iv"));
    }
    System.out.println(name + " jwtSymmetricKeySegment base64: " + split[1]);
    System.out.println(name + " jwtCryptoSegment base64: " + split[2]);

    String cleartext = WebToken.decrypt(encrypted, rsaPrivKey);
    assertEquals(joeStr, cleartext);
  }

  public void testRE128() throws Exception {
    testRsa("rsaOaepAesCbc128", rsaOaepAesCbc128HeaderStr, rsaOaepAesCbc128HeaderStrb64);
  }

  public void testRE192() throws Exception {
    testRsa("rsaOaepAesCbc192", rsaOaepAesCbc192HeaderStr, rsaOaepAesCbc192HeaderStrb64);
  }

  public void testRE256() throws Exception {
    testRsa("rsaOaepAesCbc256", rsaOaepAesCbc256HeaderStr, rsaOaepAesCbc256HeaderStrb64);
  }

  // public void testRE256Gcm() throws Exception {
  // WebToken jwt = new WebToken(joeStr, ae128);
  // }

  public void testRE128Gcm() throws Exception {
    testRsa("rsa15AesGcm128", rsa15AesGcm128HeaderStr, rsa15AesGcm128HeaderStrb64);
  }

  public void testRE256Gcm() throws Exception {
    int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
    if (maxKeyLen < 256) {
      // don't fail. Need to install
      // Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction
      // Policy Files
      return;
    }
    testRsa("rsa15AesGcm256", rsa15AesGcm256HeaderStr, rsa15AesGcm256HeaderStrb64);
  }

  public void testRE256GcmIV() throws Exception {
    int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
    if (maxKeyLen < 256) {
      // don't fail. Need to install
      // Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction
      // Policy Files
      return;
    }
    JSONObject jo = new JSONObject(rsa15AesGcm256HeaderStr);
    byte[] N = Hex.decode("cafebabefacedbaddecaf888");
    String ivB64 = Base64.encodeBytes(N, org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
    System.out.println("rsa15AesGcm256 fixed IV = " + ivB64);
    jo.put("iv", ivB64);
    String headerStr = jo.toString();
    String headerStrB64 = Base64.encodeBytes(headerStr.getBytes(), org.xmldap.util.Base64.DONT_BREAK_LINES
        | org.xmldap.util.Base64.URL);
    testRsa("rsa15AesGcm256 fixed IV", headerStr, headerStrB64);
  }

  public void testAE128() throws Exception {
    WebToken jwt = new WebToken(joeStr, ae128);

    KeyGenerator keygen;
    try {
      keygen = KeyGenerator.getInstance("AES");
    } catch (NoSuchAlgorithmException e) {
      throw new CryptoException(e);
    }

    keygen.init(128);
    SecretKey key = keygen.generateKey();

    String encrypted = jwt.encrypt(key, null);

    String[] split = encrypted.split("\\.");

    assertEquals(2, split.length);
    assertEquals(ae128b64, split[0]);

    System.out.println("AES128 jwtCryptoSegment base64: " + split[1]);

    String cleartext = WebToken.decrypt(encrypted, key);
    assertEquals(joeStr, cleartext);
  }

  private void printBytes(String label, byte[] bytes) {
    System.out.print(label + "\n[");
    for (int i = 0; i < bytes.length - 1; i++) {
      System.out.print(Integer.toString(bytes[i]) + ", ");
    }
    System.out.println(Integer.toString(bytes[bytes.length - 1]) + "]");
  }

  public void testAE192fixedKey() throws Exception {
    WebToken jwt = new WebToken(joeStr, ae192);
    byte[] encodedKey = new byte[] { 126, (byte) -34, (byte) -48, (byte) -34, (byte) 61, (byte) 72, (byte) -63,
        (byte) -36, (byte) 14, (byte) 53, (byte) -27, (byte) -7, (byte) -35, (byte) -57, (byte) 59, (byte) -89,
        (byte) 51, (byte) 84, (byte) 115, (byte) -119, (byte) -1, (byte) -125, (byte) -115, (byte) 108 };

    SecretKey key = new SecretKeySpec(encodedKey, "AES");
    printBytes("fixed AES192 keybytes", key.getEncoded());

    String encrypted = jwt.encrypt(key, null);

    String[] split = encrypted.split("\\.");

    assertEquals(2, split.length);
    assertEquals(ae192b64, split[0]);

    System.out.println("AES192 jwtCryptoSegment base64: " + split[1]);

    String cleartext = WebToken.decrypt(encrypted, key);
    assertEquals(joeStr, cleartext);

  }

  public void testAE192() throws Exception {
    WebToken jwt = new WebToken(joeStr, ae192);

    KeyGenerator keygen;
    try {
      keygen = KeyGenerator.getInstance("AES");
    } catch (NoSuchAlgorithmException e) {
      throw new CryptoException(e);
    }

    keygen.init(192);
    SecretKey key = keygen.generateKey();
    printBytes("AES192 keybytes", key.getEncoded());

    String encrypted = jwt.encrypt(key, null);

    String[] split = encrypted.split("\\.");

    assertEquals(2, split.length);
    assertEquals(ae192b64, split[0]);

    System.out.println("AES192 jwtCryptoSegment base64: " + split[1]);

    String cleartext = WebToken.decrypt(encrypted, key);
    assertEquals(joeStr, cleartext);
  }

  public void testAE256() throws Exception {
    WebToken jwt = new WebToken(joeStr, ae256);

    KeyGenerator keygen;
    try {
      keygen = KeyGenerator.getInstance("AES");
    } catch (NoSuchAlgorithmException e) {
      throw new CryptoException(e);
    }

    keygen.init(256);
    SecretKey key = keygen.generateKey();

    String encrypted = jwt.encrypt(key, null);

    String[] split = encrypted.split("\\.");

    assertEquals(2, split.length);
    assertEquals(ae256b64, split[0]);

    System.out.println("AES256 jwtCryptoSegment base64: " + split[1]);

    String cleartext = WebToken.decrypt(encrypted, key);
    assertEquals(joeStr, cleartext);
  }

  public void testAgreement() throws Exception {
    ASN1ObjectIdentifier oid = ECUtil.getNamedCurveOid("secp256r1");
    X9ECParameters x9ECParameters = ECUtil.getNamedCurveByOid(oid);
    ECCurve curve = x9ECParameters.getCurve();
    BigInteger za;
    {
      // ECPoint qB = curve.createPoint(ec256_a_X, ec256_a_Y, false);
      // ECPoint q = new ECPoint.Fp(curve, qB.getX(), qB.getY());

      ECDomainParameters ecDomainParameters = new ECDomainParameters(curve, x9ECParameters.getG(),
          x9ECParameters.getN(), x9ECParameters.getH(), x9ECParameters.getSeed());
      // ECPublicKeyParameters ecPublicKeyParameters = new
      // ECPublicKeyParameters(q, ecDomainParameters);
      ECPoint pub = x9ECParameters.getG().multiply(ec256_a_D);
      ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(pub, ecDomainParameters);

      ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(ec256_b_D, ecDomainParameters);

      ECDHBasicAgreement ecdhBasicAgreement = new ECDHBasicAgreement();
      ecdhBasicAgreement.init(ecPrivateKeyParameters);
      za = ecdhBasicAgreement.calculateAgreement(ecPublicKeyParameters);
      System.out.println("za=" + za.toString());
    }
    BigInteger zb;
    {
      // ECPoint qB = curve.createPoint(ec256_b_X, ec256_b_Y, false);
      // ECPoint q = new ECPoint.Fp(curve, qB.getX(), qB.getY());
      ECDomainParameters ecDomainParameters = new ECDomainParameters(curve, x9ECParameters.getG(),
          x9ECParameters.getN(), x9ECParameters.getH(), x9ECParameters.getSeed());
      // ECPublicKeyParameters ecPublicKeyParameters = new
      // ECPublicKeyParameters(q, ecDomainParameters);

      ECPoint pub = x9ECParameters.getG().multiply(ec256_b_D);
      ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(pub, ecDomainParameters);

      ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(ec256_a_D, ecDomainParameters);

      ECDHBasicAgreement ecdhBasicAgreement = new ECDHBasicAgreement();
      ecdhBasicAgreement.init(ecPrivateKeyParameters);
      zb = ecdhBasicAgreement.calculateAgreement(ecPublicKeyParameters);
      System.out.println("zb=" + zb.toString());
    }
    assertEquals(za.toString(), zb.toString());
  }

  public void testECencryption256() throws Exception {
    String jwtHeaderSegment = ec256_b_header;
    WebToken jwt = new WebToken(joeStr, jwtHeaderSegment);
    String encrypted = jwt.encrypt(ec256_a_X, ec256_a_Y, ec256_b_D);

    String[] split = encrypted.split("\\.");

    assertEquals(3, split.length);

    String newJwtHeaderSegment = new String(Base64.decodeUrl(split[0]));
    JSONObject newJwtHeader = new JSONObject(newJwtHeaderSegment);
    JSONObject oldJwtHeader = new JSONObject(jwtHeaderSegment);

    assertEquals(oldJwtHeader.get("alg"), newJwtHeader.get("alg"));
    assertEquals(oldJwtHeader.get("enc"), newJwtHeader.get("enc"));
    String ivB64 = oldJwtHeader.optString("iv", null);
    if (ivB64 != null) {
      assertEquals(ivB64, newJwtHeader.get("iv"));
    }
    System.out.println("ECDH-ES jwtHeaderSegment: " + jwtHeaderSegment);
    System.out.println("ECDH-ES jwtHeaderSegment base64: " + split[0]);
    System.out.println("ECDH-ES jwtSymmetricKeySegment base64: " + split[1]);
    System.out.println("ECDH-ES jwtCryptoSegment base64: " + split[2]);

    // TODO use x,y from the newHeader epk
    String cleartext = WebToken.decrypt(encrypted, ec256_b_X, ec256_b_Y, ec256_a_D);
    assertEquals(joeStr, cleartext);
  }

  public void testECencryptionEphemeralKey() throws Exception {
    String curveName = "secp256r1";
    ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(curveName);

    KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", new BouncyCastleProvider());

    g.initialize(ecGenSpec, new SecureRandom());

    // java.lang.ClassCastException:
    // org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey cannot be
    // cast to org.bouncycastle.asn1.sec.ECPrivateKey

    KeyPair pair = g.generateKeyPair();
    BCECPublicKey publicKey = (BCECPublicKey) pair.getPublic();
    BCECPrivateKey privateKey = (BCECPrivateKey) pair.getPrivate();

    // Bouncycastle
    BigInteger X = publicKey.getQ().getX().toBigInteger();
    BigInteger Y = publicKey.getQ().getY().toBigInteger();
    BigInteger D = privateKey.getD();

    // JCE
    // BigInteger X = publicKey.getQ().getAffineX();
    // BigInteger Y = publicKey.getQ().getAffineY();
    // BigInteger D = privateKey.getS();
    String X_b64 = Base64.encodeBytes(X.toByteArray(), org.xmldap.util.Base64.DONT_BREAK_LINES
        | org.xmldap.util.Base64.URL);
    String Y_b64 = Base64.encodeBytes(Y.toByteArray(), org.xmldap.util.Base64.DONT_BREAK_LINES
        | org.xmldap.util.Base64.URL);
    String D_b64 = Base64.encodeBytes(D.toByteArray(), org.xmldap.util.Base64.DONT_BREAK_LINES
        | org.xmldap.util.Base64.URL);
    System.out.println("ECDH-ES D base64=" + D_b64);

    String header = "{\"alg\":\"ECDH-ES\",\r\n" + "\"enc\":\"" + WebToken.ENC_ALG_A256GCM + "\",\r\n"
        + "\"iv\":\"__79_Pv6-fg\",\r\n" + "\"epk\": {\"jwk\": [{\r\n" + " \"crv\":\"" + curveName + "\",\r\n"
        + " \"x\":\"" + X_b64 + "\",\r\n" + " \"y\":\"" + Y_b64 + "\"}]}}";

    String jwtHeaderSegment = header;
    WebToken jwt = new WebToken(joeStr, jwtHeaderSegment);
    String encrypted = jwt.encrypt(ec256_b_X, ec256_b_Y, D);

    String[] split = encrypted.split("\\.");

    assertEquals(3, split.length);

    String newJwtHeaderSegment = new String(Base64.decodeUrl(split[0]));
    JSONObject newJwtHeader = new JSONObject(newJwtHeaderSegment);
    JSONObject oldJwtHeader = new JSONObject(jwtHeaderSegment);

    assertEquals(oldJwtHeader.get("alg"), newJwtHeader.get("alg"));
    assertEquals(oldJwtHeader.get("enc"), newJwtHeader.get("enc"));
    String ivB64 = oldJwtHeader.optString("iv", null);
    if (ivB64 != null) {
      assertEquals(ivB64, newJwtHeader.get("iv"));
    }
    System.out.println("ECDH-ES jwtHeaderSegment: " + jwtHeaderSegment);
    System.out.println("ECDH-ES jwtHeaderSegment base64: " + split[0]);
    System.out.println("ECDH-ES jwtSymmetricKeySegment base64: " + split[1]);
    System.out.println("ECDH-ES jwtCryptoSegment base64: " + split[2]);

    // TODO use x,y from header
    String cleartext = WebToken.decrypt(encrypted, X, Y, ec256_b_D);
    assertEquals(joeStr, cleartext);
  }

  // public void testMikesExample2() throws Exception {
  // byte[] cmk = {
  // (byte)177, (byte)161, (byte)244, (byte)128, (byte)84, (byte)143, (byte)225,
  // (byte)115, (byte)63, (byte)180,
  // (byte)3, (byte)255, (byte)107, (byte)154, (byte)212, (byte)246, (byte)138,
  // (byte)7, (byte)110, (byte)91,
  // (byte)112, (byte)46, (byte)34, (byte)105, (byte)47, (byte)130, (byte)203,
  // (byte)46, (byte)122, (byte)234,
  // (byte)64, (byte)252};
  // SecretKey contentEncryptionKey = new SecretKeySpec(cmk, "raw");
  // byte[] ivBytes = {
  // (byte)227, (byte)197, (byte)117, (byte)252, (byte)2, (byte)219,
  // (byte)233, (byte)68, (byte)180, (byte)225, (byte)77, (byte)219};
  // byte[] plainTextBytes = {
  // 76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32, 112, 114,
  // 111, 115, 112, 101, 114, 46};
  // String jwtHeaderStr =
  // "{\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\",\"iv\":\"48V1_ALb6US04U3b\"}";
  // String ivBytesB64 = Base64.encodeBytes(ivBytes,
  // org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
  // assertEquals("48V1_ALb6US04U3b", ivBytesB64);
  // byte[] headerBytes = {
  // 123, 34, 97, 108, 103, 34, 58, 34, 82, 83, 65, 45, 79, 65, 69, 80,
  // 34, 44, 34, 101, 110, 99, 34, 58, 34, 65, 50, 53, 54, 71, 67, 77,
  // 34, 44, 34, 105, 118, 34, 58, 34, 52, 56, 86, 49, 95, 65, 76, 98,
  // 54, 85, 83, 48, 52, 85, 51, 98, 34, 125
  // };
  // assertEquals(jwtHeaderStr, new String(headerBytes, "UTF-8"));
  // String encodedHeader =
  // "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00iLCJpdiI6IjQ4VjFfQUxiNlVTMDRVM2IifQ";
  // assertEquals(encodedHeader,
  // Base64.encodeBytes(headerBytes, org.xmldap.util.Base64.DONT_BREAK_LINES |
  // org.xmldap.util.Base64.URL));
  //
  //
  // RSAPublicKey publicKey;
  // RSAPrivateKey privKey;
  // {
  // byte[] e = {1,0,1};
  // BigInteger E = new BigInteger(1, e);
  // byte[] n = {
  // (byte)161, (byte)168, (byte)84, (byte)34, (byte)133, (byte)176, (byte)208,
  // (byte)173, (byte)46, (byte)176, (byte)163, (byte)110, (byte)57, (byte)30,
  // (byte)135, (byte)227,
  // (byte)9, (byte)31, (byte)226, (byte)128, (byte)84, (byte)92, (byte)116,
  // (byte)241, (byte)70, (byte)248, (byte)27, (byte)227, (byte)193, (byte)62,
  // (byte)5, (byte)91,
  // (byte)241, (byte)145, (byte)224, (byte)205, (byte)141, (byte)176,
  // (byte)184, (byte)133, (byte)239, (byte)43, (byte)81, (byte)103, (byte)9,
  // (byte)161, (byte)153, (byte)157,
  // (byte)179, (byte)104, (byte)123, (byte)51, (byte)189, (byte)34, (byte)152,
  // (byte)69, (byte)97, (byte)69, (byte)78, (byte)93, (byte)140, (byte)131,
  // (byte)87, (byte)182,
  // (byte)169, (byte)101, (byte)92, (byte)142, (byte)3, (byte)22, (byte)167,
  // (byte)8, (byte)212, (byte)56, (byte)35, (byte)79, (byte)210, (byte)222,
  // (byte)192, (byte)208,
  // (byte)252, (byte)49, (byte)109, (byte)138, (byte)173, (byte)253, (byte)210,
  // (byte)166, (byte)201, (byte)63, (byte)102, (byte)74, (byte)5, (byte)158,
  // (byte)41, (byte)90,
  // (byte)144, (byte)108, (byte)160, (byte)79, (byte)10, (byte)89, (byte)222,
  // (byte)231, (byte)172, (byte)31, (byte)227, (byte)197, (byte)0, (byte)19,
  // (byte)72, (byte)81,
  // (byte)138, (byte)78, (byte)136, (byte)221, (byte)121, (byte)118, (byte)196,
  // (byte)17, (byte)146, (byte)10, (byte)244, (byte)188, (byte)72, (byte)113,
  // (byte)55, (byte)221,
  // (byte)162, (byte)217, (byte)171, (byte)27, (byte)57, (byte)233, (byte)210,
  // (byte)101, (byte)236, (byte)154, (byte)199, (byte)56, (byte)138, (byte)239,
  // (byte)101, (byte)48,
  // (byte)198, (byte)186, (byte)202, (byte)160, (byte)76, (byte)111, (byte)234,
  // (byte)71, (byte)57, (byte)183, (byte)5, (byte)211, (byte)171, (byte)136,
  // (byte)126, (byte)64,
  // (byte)40, (byte)75, (byte)58, (byte)89, (byte)244, (byte)254, (byte)107,
  // (byte)84, (byte)103, (byte)7, (byte)236, (byte)69, (byte)163, (byte)18,
  // (byte)180, (byte)251,
  // (byte)58, (byte)153, (byte)46, (byte)151, (byte)174, (byte)12, (byte)103,
  // (byte)197, (byte)181, (byte)161, (byte)162, (byte)55, (byte)250, (byte)235,
  // (byte)123, (byte)110,
  // (byte)17, (byte)11, (byte)158, (byte)24, (byte)47, (byte)133, (byte)8,
  // (byte)199, (byte)235, (byte)107, (byte)126, (byte)130, (byte)246, (byte)73,
  // (byte)195, (byte)20,
  // (byte)108, (byte)202, (byte)176, (byte)214, (byte)187, (byte)45, (byte)146,
  // (byte)182, (byte)118, (byte)54, (byte)32, (byte)200, (byte)61, (byte)201,
  // (byte)71, (byte)243,
  // (byte)1, (byte)255, (byte)131, (byte)84, (byte)37, (byte)111, (byte)211,
  // (byte)168, (byte)228, (byte)45, (byte)192, (byte)118, (byte)27, (byte)197,
  // (byte)235, (byte)232,
  // (byte)36, (byte)10, (byte)230, (byte)248, (byte)190, (byte)82, (byte)182,
  // (byte)140, (byte)35, (byte)204, (byte)108, (byte)190, (byte)253, (byte)186,
  // (byte)186, (byte)27
  // };
  // BigInteger N = new BigInteger(1, n);
  // byte[] d = {
  // (byte)144, (byte)183, (byte)109, (byte)34, (byte)62, (byte)134, (byte)108,
  // (byte)57, (byte)44, (byte)252, (byte)10, (byte)66, (byte)73, (byte)54,
  // (byte)16, (byte)181,
  // (byte)233, (byte)92, (byte)54, (byte)219, (byte)101, (byte)42, (byte)35,
  // (byte)178, (byte)63, (byte)51, (byte)43, (byte)92, (byte)119, (byte)136,
  // (byte)251, (byte)41,
  // (byte)53, (byte)23, (byte)191, (byte)164, (byte)164, (byte)60, (byte)88,
  // (byte)227, (byte)229, (byte)152, (byte)228, (byte)213, (byte)149,
  // (byte)228, (byte)169, (byte)237,
  // (byte)104, (byte)71, (byte)151, (byte)75, (byte)88, (byte)252, (byte)216,
  // (byte)77, (byte)251, (byte)231, (byte)28, (byte)97, (byte)88, (byte)193,
  // (byte)215, (byte)202,
  // (byte)248, (byte)216, (byte)121, (byte)195, (byte)211, (byte)245,
  // (byte)250, (byte)112, (byte)71, (byte)243, (byte)61, (byte)129, (byte)95,
  // (byte)39, (byte)244, (byte)122,
  // (byte)225, (byte)217, (byte)169, (byte)211, (byte)165, (byte)48, (byte)253,
  // (byte)220, (byte)59, (byte)122, (byte)219, (byte)42, (byte)86, (byte)223,
  // (byte)32, (byte)236,
  // (byte)39, (byte)48, (byte)103, (byte)78, (byte)122, (byte)216, (byte)187,
  // (byte)88, (byte)176, (byte)89, (byte)24, (byte)1, (byte)42, (byte)177,
  // (byte)24, (byte)99,
  // (byte)142, (byte)170, (byte)1, (byte)146, (byte)43, (byte)3, (byte)108,
  // (byte)64, (byte)194, (byte)121, (byte)182, (byte)95, (byte)187, (byte)134,
  // (byte)71, (byte)88,
  // (byte)96, (byte)134, (byte)74, (byte)131, (byte)167, (byte)69, (byte)106,
  // (byte)143, (byte)121, (byte)27, (byte)72, (byte)44, (byte)245, (byte)95,
  // (byte)39, (byte)194,
  // (byte)179, (byte)175, (byte)203, (byte)122, (byte)16, (byte)112, (byte)183,
  // (byte)17, (byte)200, (byte)202, (byte)31, (byte)17, (byte)138, (byte)156,
  // (byte)184, (byte)210,
  // (byte)157, (byte)184, (byte)154, (byte)131, (byte)128, (byte)110, (byte)12,
  // (byte)85, (byte)195, (byte)122, (byte)241, (byte)79, (byte)251, (byte)229,
  // (byte)183, (byte)117,
  // (byte)21, (byte)123, (byte)133, (byte)142, (byte)220, (byte)153, (byte)9,
  // (byte)59, (byte)57, (byte)105, (byte)81, (byte)255, (byte)138, (byte)77,
  // (byte)82, (byte)54,
  // (byte)62, (byte)216, (byte)38, (byte)249, (byte)208, (byte)17, (byte)197,
  // (byte)49, (byte)45, (byte)19, (byte)232, (byte)157, (byte)251, (byte)131,
  // (byte)137, (byte)175,
  // (byte)72, (byte)126, (byte)43, (byte)229, (byte)69, (byte)179, (byte)117,
  // (byte)82, (byte)157, (byte)213, (byte)83, (byte)35, (byte)57, (byte)210,
  // (byte)197, (byte)252,
  // (byte)171, (byte)143, (byte)194, (byte)11, (byte)47, (byte)163, (byte)6,
  // (byte)253, (byte)75, (byte)252, (byte)96, (byte)11, (byte)187, (byte)84,
  // (byte)130, (byte)210,
  // (byte)7, (byte)121, (byte)78, (byte)91, (byte)79, (byte)57, (byte)251,
  // (byte)138, (byte)132, (byte)220, (byte)60, (byte)224, (byte)173, (byte)56,
  // (byte)224, (byte)201
  // };
  // BigInteger D = new BigInteger(1, d);
  //
  // KeyFactory keyFactory = KeyFactory.getInstance("RSA");
  // RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(N, E);
  // RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(N, D);
  // publicKey = (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);
  // privKey = (RSAPrivateKey) keyFactory.generatePrivate(privKeySpec);
  //
  // String name = "Mikes Example2";
  // System.out.println("jwtHeaderSegment: " + name + " " + jwtHeaderStr);
  // System.out.println("jwtHeaderSegment: " + name + " " + encodedHeader);
  //
  // String plainText = new String(plainTextBytes);
  // WebToken jwt = new WebToken(plainText, jwtHeaderStr);
  // String encrypted = jwt.encrypt(publicKey, contentEncryptionKey);
  //
  // String[] split = encrypted.split("\\.");
  //
  // assertEquals(3, split.length);
  //
  // String newJwtHeaderSegment = new String(Base64.decodeUrl(split[0]));
  // JSONObject newJwtHeader = new JSONObject(newJwtHeaderSegment);
  // JSONObject oldJwtHeader = new JSONObject(jwtHeaderStr);
  //
  // assertEquals(oldJwtHeader.get("alg"), newJwtHeader.get("alg"));
  // assertEquals(oldJwtHeader.get("enc"), newJwtHeader.get("enc"));
  // String ivB64 = oldJwtHeader.optString("iv", null);
  // assertEquals(ivB64, newJwtHeader.get("iv"));
  // System.out.println(name + " jwtSymmetricKeySegment base64: " + split[1]);
  // System.out.println(name + " jwtCryptoSegment base64: " + split[2]);
  //
  // String cleartext = WebToken.decrypt(encrypted, privKey);
  // assertEquals(plainText, cleartext);
  //
  // String jwe =
  // "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00iLCJpdiI6IjQ4VjFfQUxiNlVTMDRVM2IifQ.jvwoyhWxOMboB5cxX6ncAi7Wp3Q5FKRtlmIx35pfR9HpEa6Oy-iEpxEqM30W3YcRQ8WU9ouRoO5jd6tfdcpX-2X-OteHw4dnMXdMLjHGGx86LMDeFRAN2KGz7EGPJivaw0yM80fzT3zY0PKrIvU5ml1M5szqUnX4Jw0-PNcIM_j-L5YkLhv3Yk04XCwTJwxNNmXCflYAQO9f00Aa213TJJr6dbHV6I642FwU-EWvtEfN3evgX3EFIVYSnT3HCHkAAIdBQ9ykD-abRzVA_dGp_yJAZQcrZuNTqzThd_22YMPhIpzTygfC_4k7qqxI6t7Le_l5_o-taUG7vaNAl5FjEQ._e21tGGhac_peEFkLXr2dMPUZiUkrw.YbZSeHCNDZBqAdzpROlyiw";
  // split = jwe.split("\\.");
  //
  // assertEquals(4, split.length);
  // newJwtHeaderSegment = new String(Base64.decodeUrl(split[0]));
  //
  // System.out.println(name + " jwtHeader base64: " + split[0]);
  // System.out.println(name + " jwtSymmetricKeySegment base64: " + split[1]);
  // System.out.println(name + " jwtCryptoSegment base64: " + split[2]);
  // System.out.println(name + " jwtAuthnSegment base64: " + split[3]);
  //
  //
  // newJwtHeader = new JSONObject(newJwtHeaderSegment);
  // assertEquals(oldJwtHeader.get("alg"), newJwtHeader.get("alg"));
  // assertEquals(oldJwtHeader.get("enc"), newJwtHeader.get("enc"));
  // ivB64 = oldJwtHeader.optString("iv", null);
  // assertEquals(ivB64, newJwtHeader.get("iv"));
  //
  // cleartext = WebToken.decrypt(jwe, privKey);
  // assertEquals(plainText, cleartext);
  //
  // }
  // }

  //
  // http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-04#appendix-A.1
  //
  public void testJWEExampleRSAESOAEPWithIntegrity() throws Exception {
    String plaintext = "Live long and prosper.";
    byte[] plaintextBytes = { 76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32, 112, 114, 111, 115, 112,
        101, 114, 46 };
    assertTrue(Arrays.equals(plaintext.getBytes(), plaintextBytes));

    String ivB64 = "48V1_ALb6US04U3b";
    String headerStr = "{\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\",\"iv\":\"48V1_ALb6US04U3b\"}";
    String headerStrB64 = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00iLCJpdiI6IjQ4VjFfQUxiNlVTMDRVM2IifQ";
    assertEquals(headerStrB64,
        Base64.encodeBytes(headerStr.getBytes(), org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL));
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

    WebToken jwt = new WebToken(plaintext, headerStr);
    SecretKey contentEncryptionKey = new SecretKeySpec(cmk, "AES");
    String encrypted = jwt.encrypt(aRsaPublicKey, contentEncryptionKey);
    String[] split = encrypted.split("\\.");
    assertEquals(4, split.length);

    String cleartext = WebToken.decrypt(encrypted, aRsaPrivKey);
    assertEquals(plaintext, cleartext);
  }

  //
  // http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-04#appendix-A.2
  //
  public void testJWEExampleRSAESPKCS1V1_5andAESCBC() throws Exception {
    String plaintext = "Now is the time for all good men to come to the aid of their country.";
    byte[] plaintextBytes = {78, 111, 119, 32, 105, 115, 32, 116, 104, 101, 32, 116, 105, 109,
        101, 32, 102, 111, 114, 32, 97, 108, 108, 32, 103, 111, 111, 100, 32,
        109, 101, 110, 32, 116, 111, 32, 99, 111, 109, 101, 32, 116, 111, 32,
        116, 104, 101, 32, 97, 105, 100, 32, 111, 102, 32, 116, 104, 101,
        105, 114, 32, 99, 111, 117, 110, 116, 114, 121, 46};
    assertTrue(Arrays.equals(plaintext.getBytes(), plaintextBytes));

    String headerStr = "{\"alg\":\"RSA1_5\",\"enc\":\"A128CBC\",\"int\":\"HS256\",\"iv\":\"AxY8DCtDaGlsbGljb3RoZQ\"}";
    String headerStrB64 = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDIiwiaW50IjoiSFMyNTYiLCJpdiI6IkF4WThEQ3REYUdsc2JHbGpiM1JvWlEifQ";
    assertEquals(headerStrB64,
        Base64.encodeBytes(headerStr.getBytes(), org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL));

    final byte[] cmk = {(byte)4, (byte)211, (byte)31, (byte)197, (byte)84, (byte)157, (byte)252, (byte)254, (byte)11, (byte)100, (byte)157, (byte)250, (byte)63, (byte)170, (byte)106,
        (byte)206, (byte)107, (byte)124, (byte)212, (byte)45, (byte)111, (byte)107, (byte)9, (byte)219, (byte)200, (byte)177, (byte)0, (byte)240, (byte)143, (byte)156,
        (byte)44, (byte)207};
    final byte[] n = { (byte)177, (byte)119, (byte)33, (byte)13, (byte)164, (byte)30, (byte)108, (byte)121,
        (byte)207, (byte)136, (byte)107, (byte)(byte)242, (byte)12, (byte)224, (byte)19, (byte)226,
        (byte)198, (byte)134, (byte)17, (byte)71, (byte)173, (byte)75, (byte)42, (byte)(byte)61, (byte)48,
        (byte)162, (byte)206, (byte)161, (byte)97, (byte)108, (byte)185, (byte)234, (byte)226, (byte)219,
        (byte)(byte)118, (byte)206, (byte)118, (byte)5, (byte)169, (byte)224, (byte)60, (byte)181, (byte)90,
        (byte)85, (byte)51, (byte)123, (byte)(byte)6, (byte)224, (byte)4, (byte)122, (byte)29, (byte)230,
        (byte)151, (byte)12, (byte)244, (byte)127, (byte)121, (byte)25, (byte)(byte)4, (byte)85, (byte)220,
        (byte)144, (byte)215, (byte)110, (byte)130, (byte)17, (byte)68, (byte)228, (byte)129,
        (byte)(byte)138, (byte)7, (byte)130, (byte)231, (byte)40, (byte)212, (byte)214, (byte)17, (byte)179,
        (byte)28, (byte)124, (byte)(byte)151, (byte)178, (byte)207, (byte)20, (byte)14, (byte)154, (byte)222,
        (byte)113, (byte)176, (byte)24, (byte)198, (byte)(byte)73, (byte)211, (byte)113, (byte)9, (byte)33,
        (byte)178, (byte)80, (byte)13, (byte)25, (byte)21, (byte)25, (byte)153, (byte)(byte)212, (byte)206,
        (byte)67, (byte)154, (byte)147, (byte)70, (byte)194, (byte)192, (byte)183, (byte)160, (byte)83,
        (byte)(byte)98, (byte)236, (byte)175, (byte)85, (byte)23, (byte)97, (byte)75, (byte)199, (byte)177,
        (byte)73, (byte)145, (byte)50, (byte)(byte)253, (byte)206, (byte)32, (byte)179, (byte)254, (byte)236,
        (byte)190, (byte)82, (byte)73, (byte)67, (byte)129, (byte)(byte)253, (byte)252, (byte)220, (byte)108,
        (byte)136, (byte)138, (byte)11, (byte)192, (byte)1, (byte)36, (byte)239, (byte)(byte)228, (byte)55,
        (byte)81, (byte)113, (byte)17, (byte)25, (byte)140, (byte)63, (byte)239, (byte)146, (byte)3,
        (byte)172, (byte)(byte)96, (byte)60, (byte)227, (byte)233, (byte)64, (byte)255, (byte)224, (byte)173,
        (byte)225, (byte)228, (byte)229, (byte)(byte)92, (byte)112, (byte)72, (byte)99, (byte)97, (byte)26,
        (byte)87, (byte)187, (byte)123, (byte)46, (byte)50, (byte)90, (byte)(byte)202, (byte)117, (byte)73,
        (byte)10, (byte)153, (byte)47, (byte)224, (byte)178, (byte)163, (byte)77, (byte)48, (byte)46,
        (byte)(byte)154, (byte)33, (byte)148, (byte)34, (byte)228, (byte)33, (byte)172, (byte)216, (byte)89,
        (byte)46, (byte)225, (byte)(byte)127, (byte)68, (byte)146, (byte)234, (byte)30, (byte)147, (byte)54,
        (byte)146, (byte)5, (byte)133, (byte)45, (byte)78, (byte)(byte)254, (byte)85, (byte)55, (byte)75,
        (byte)213, (byte)86, (byte)194, (byte)218, (byte)215, (byte)163, (byte)189, (byte)(byte)194,
        (byte)54, (byte)6, (byte)83, (byte)36, (byte)18, (byte)153, (byte)53, (byte)7, (byte)48, (byte)89,
        (byte)35, (byte)66, (byte)(byte)144, (byte)7, (byte)65, (byte)154, (byte)13, (byte)97, (byte)75,
        (byte)55, (byte)230, (byte)132, (byte)3, (byte)13, (byte)(byte)239, (byte)71 };
    final byte[] e = { 1, 0, 1 };
    final byte[] d = { (byte) 84, (byte) 80, (byte) 150, (byte) 58, (byte) 165, (byte) 235, (byte) 242, (byte) 123,
        (byte) 217, (byte) 55, (byte) 38, (byte) (byte) 154, (byte) 36, (byte) 181, (byte) 221, (byte) 156, (byte) 211,
        (byte) 215, (byte) 100, (byte) 164, (byte) 90, (byte) 88, (byte) (byte) 40, (byte) 228, (byte) 83, (byte) 148,
        (byte) 54, (byte) 122, (byte) 4, (byte) 16, (byte) 165, (byte) 48, (byte) 76, (byte) 194, (byte) (byte) 26,
        (byte) 107, (byte) 51, (byte) 53, (byte) 179, (byte) 165, (byte) 31, (byte) 18, (byte) 198, (byte) 173,
        (byte) 78, (byte) 61, (byte) (byte) 56, (byte) 97, (byte) 252, (byte) 158, (byte) 140, (byte) 80, (byte) 63,
        (byte) 25, (byte) 223, (byte) 156, (byte) 36, (byte) 203, (byte) (byte) 214, (byte) 252, (byte) 120, (byte) 67,
        (byte) 180, (byte) 167, (byte) 3, (byte) 82, (byte) 243, (byte) 25, (byte) 97, (byte) 214, (byte) (byte) 83,
        (byte) 133, (byte) 69, (byte) 16, (byte) 104, (byte) 54, (byte) 160, (byte) 200, (byte) 41, (byte) 83,
        (byte) 164, (byte) 187, (byte) (byte) 70, (byte) 153, (byte) 111, (byte) 234, (byte) 242, (byte) 158,
        (byte) 175, (byte) 28, (byte) 198, (byte) 48, (byte) 211, (byte) (byte) 45, (byte) 148, (byte) 58, (byte) 23,
        (byte) 62, (byte) 227, (byte) 74, (byte) 52, (byte) 117, (byte) 42, (byte) 90, (byte) 41, (byte) (byte) 249,
        (byte) 130, (byte) 154, (byte) 80, (byte) 119, (byte) 61, (byte) 26, (byte) 193, (byte) 40, (byte) 125,
        (byte) 10, (byte) (byte) 152, (byte) 174, (byte) 227, (byte) 225, (byte) 205, (byte) 32, (byte) 62, (byte) 66,
        (byte) 6, (byte) 163, (byte) 100, (byte) 99, (byte) (byte) 219, (byte) 19, (byte) 253, (byte) 25, (byte) 105,
        (byte) 80, (byte) 201, (byte) 29, (byte) 252, (byte) 157, (byte) 237, (byte) (byte) 69, (byte) 1, (byte) 80,
        (byte) 171, (byte) 167, (byte) 20, (byte) 196, (byte) 156, (byte) 109, (byte) 249, (byte) 88, (byte) 0,
        (byte) (byte) 3, (byte) 152, (byte) 38, (byte) 165, (byte) 72, (byte) 87, (byte) 6, (byte) 152, (byte) 71,
        (byte) 156, (byte) 214, (byte) 16, (byte) (byte) 71, (byte) 30, (byte) 82, (byte) 51, (byte) 103, (byte) 76,
        (byte) 218, (byte) 63, (byte) 9, (byte) 84, (byte) 163, (byte) 249, (byte) (byte) 91, (byte) 215, (byte) 44,
        (byte) 238, (byte) 85, (byte) 101, (byte) 240, (byte) 148, (byte) 1, (byte) 82, (byte) 224, (byte) 91,
        (byte) (byte) 135, (byte) 105, (byte) 127, (byte) 84, (byte) 171, (byte) 181, (byte) 152, (byte) 210,
        (byte) 183, (byte) 126, (byte) 24, (byte) (byte) 46, (byte) 196, (byte) 90, (byte) 173, (byte) 38, (byte) 245,
        (byte) 219, (byte) 186, (byte) 222, (byte) 27, (byte) 240, (byte) (byte) 212, (byte) 194, (byte) 15, (byte) 66,
        (byte) 135, (byte) 226, (byte) 178, (byte) 190, (byte) 52, (byte) 245, (byte) 74, (byte) (byte) 65, (byte) 224,
        (byte) 81, (byte) 100, (byte) 85, (byte) 25, (byte) 204, (byte) 165, (byte) 203, (byte) 187, (byte) 175,
        (byte) (byte) 84, (byte) 100, (byte) 82, (byte) 15, (byte) 11, (byte) 23, (byte) 202, (byte) 151, (byte) 107,
        (byte) 54, (byte) 41, (byte) 207, (byte) (byte) 3, (byte) 136, (byte) 229, (byte) 134, (byte) 131, (byte) 93,
        (byte) 139, (byte) 50, (byte) 182, (byte) 204, (byte) 93, (byte) (byte) 130, (byte)89};

    BigInteger N = new BigInteger(1, n);
    BigInteger E = new BigInteger(1, e);
    BigInteger D = new BigInteger(1, d);

    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(N, E);
    RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(N, D);
    RSAPublicKey aRsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);
    RSAPrivateKey aRsaPrivKey = (RSAPrivateKey) keyFactory.generatePrivate(privKeySpec);

    WebToken jwt = new WebToken(plaintext, headerStr);
    SecretKey contentEncryptionKey = new SecretKeySpec(cmk, "AES");
    String encrypted = jwt.encrypt(aRsaPublicKey, contentEncryptionKey);
    String[] split = encrypted.split("\\.");
    assertEquals(4, split.length);

    String cleartext = WebToken.decrypt(encrypted, aRsaPrivKey);
    assertEquals(plaintext, cleartext);
  }
}
