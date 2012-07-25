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
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import net.sourceforge.lightcrypto.SafeObject;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jcajce.provider.asymmetric.ec.ECUtil;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.xmldap.crypto.CryptoUtils;
import org.xmldap.crypto.KDFConcatGenerator;
import org.xmldap.util.Base64;

public class WebToken {

  public static final String SIGN_ALG_HS256 = "HS256";
  public static final String SIGN_ALG_HS383 = "HS384";
  public static final String SIGN_ALG_HS512 = "HS512";

  public static final String SIGN_ALG_ES256 = "ES256";
  public static final String SIGN_ALG_ES383 = "ES384";
  public static final String SIGN_ALG_ES512 = "ES512";

  public static final String SIGN_ALG_RS256 = "RS256";
  public static final String SIGN_ALG_RS383 = "RS384";
  public static final String SIGN_ALG_RS512 = "RS512";

  public static final String ENC_ALG_RE128 = "RE128"; // RSA-OAEP encrypted
                                                      // AES-CBC key with 128
                                                      // bits
  public static final String ENC_ALG_RE192 = "RE192"; // RSA-OAEP encrypted
                                                      // AES-CBC key with 192
                                                      // bits
  public static final String ENC_ALG_RE256 = "RE256"; // RSA-OAEP encrypted
                                                      // AES-CBC key with 256
                                                      // bits

  public static final String ENC_ALG_AE128 = "AE128"; // AES-CBC with 128 bit
                                                      // key size
  public static final String ENC_ALG_AE192 = "AE192"; // AES-CBC with 192 bit
                                                      // key size
  public static final String ENC_ALG_AE256 = "AE256"; // AES-CBC with 256 bit
                                                      // key size

  public static final String ENC_ALG_PE820 = "PE820"; // Password based
                                                      // encryption with 8 byte
                                                      // salt and 20 rounds

  // RSA using RSA-PKCS1-1.5 padding RSA1_5
  // http://www.w3.org/2001/04/xmlenc#rsa-1_5 RSA/ECB/PKCS1Padding TBD
  // RSA using Optimal Asymmetric Encryption Padding (OAEP) RSA-OAEP
  // http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p
  // RSA/ECB/OAEPWithSHA-1AndMGF1Padding TBD
  // Elliptic Curve Diffie-Hellman Ephemeral Static ECDH-ES
  // http://www.w3.org/2009/xmlenc11#ECDH-ES TBD TBD
  // Advanced Encryption Standard (AES) Key Wrap Algorithm RFC 3394 [RFC3394]
  // using 128 bit keys A128KW http://www.w3.org/2001/04/xmlenc#kw-aes128 TBD
  // TBD
  // Advanced Encryption Standard (AES) Key Wrap Algorithm RFC 3394 [RFC3394]
  // using 256 bit keys A256KW http://www.w3.org/2001/04/xmlenc#kw-aes256 TBD
  // TBD
  // Advanced Encryption Standard (AES) using 128 bit keys in Cipher Block
  // Chaining mode A128CBC http://www.w3.org/2001/04/xmlenc#aes128-cbc
  // AES/CBC/PKCS5Padding TBD
  // Advanced Encryption Standard (AES) using 256 bit keys in Cipher Block
  // Chaining mode A256CBC http://www.w3.org/2001/04/xmlenc#aes256-cbc
  // AES/CBC/PKCS5Padding TBD
  // Advanced Encryption Standard (AES) using 128 bit keys in Galois/Counter
  // Mode A128GCM http://www.w3.org/2009/xmlenc11#aes128-gcm AES/GCM/NoPadding
  // TBD
  // Advanced Encryption Standard (AES) using 256 bit keys in Galois/Counter
  // Mode A256GCM http://www.w3.org/2009/xmlenc11#aes256-gcm AES/GCM/NoPadding
  // TBD

  public static final String ENC_ALG_RSA1_5 = "RSA1_5";
  public static final String ENC_ALG_RSA_OAEP = "RSA-OAEP";
  public static final String ENC_ALG_ECDH_ES = "ECDH-ES";
  public static final String ENC_ALG_A128KW = "A128KW";
  public static final String ENC_ALG_A256KW = "A256KW";
  public static final String ENC_ALG_A128CBC = "A128CBC";
  public static final String ENC_ALG_A192CBC = "A192CBC";
  public static final String ENC_ALG_A256CBC = "A256CBC";
  public static final String ENC_ALG_A512CBC = "A512CBC";
  public static final String ENC_ALG_A128GCM = "A128GCM";
  public static final String ENC_ALG_A192GCM = "A192GCM";
  public static final String ENC_ALG_A256GCM = "A256GCM";
  public static final String ENC_ALG_A512GCM = "A512GCM";

  String mJsonStr = null;
  PrivateKey mPrivateKey = null;
  JSONObject mHeader;
  String mHeaderStr;

  public WebToken(String jso, JSONObject header) throws JSONException {
    mJsonStr = jso;
    mHeader = header;
    mHeaderStr = header.toString();
  }

  public WebToken(String jso, String headerStr) throws JSONException {
    mJsonStr = jso;
    mHeader = new JSONObject(headerStr);
    mHeaderStr = headerStr;
  }

  static public boolean verify(String jwt, RSAPublicKey pubkey) throws Exception {
    String jwtHeaderSegment;
    String jwtPayloadSegment;
    String jwtCryptoSegment;
    String[] split = jwt.split("\\.");
    jwtHeaderSegment = split[0];
    jwtPayloadSegment = split[1];
    jwtCryptoSegment = split[2];

    String algorithm;
    JSONObject header = new JSONObject(jwtHeaderSegment);
    String jwtAlgStr = (String) header.get("alg");
    if ("RS256".equals(jwtAlgStr)) {
      algorithm = "SHA256withRSA";
    } else if ("RS384".equals(jwtAlgStr)) {
      algorithm = "SHA384withRSA";
    } else if ("RS512".equals(jwtAlgStr)) {
      algorithm = "SHA512withRSA";
    } else {
      throw new NoSuchAlgorithmException("JWT algorithm: " + jwtAlgStr);
    }

    String stringToSign = jwtHeaderSegment + "." + jwtPayloadSegment;
    Signature signature = Signature.getInstance(algorithm);
    signature.initVerify(pubkey);
    signature.update(stringToSign.getBytes("utf-8"));

    byte[] signatureBytes = Base64.decodeUrl(jwtCryptoSegment);

    return signature.verify(signatureBytes);
  }

  static public boolean verify(String jwt, byte[] x, byte[] y) throws Exception {
    String jwtHeaderSegment;
    String jwtPayloadSegment;
    String jwtCryptoSegment;
    String[] split = jwt.split("\\.");
    jwtHeaderSegment = split[0];
    jwtPayloadSegment = split[1];
    jwtCryptoSegment = split[2];

    byte[] signatureBytes = Base64.decodeUrl(jwtCryptoSegment);
    byte[] rBytes = new byte[32];
    System.arraycopy(signatureBytes, 0, rBytes, 0, 32);
    byte[] sBytes = new byte[32];
    System.arraycopy(signatureBytes, 32, sBytes, 0, 32);

    BigInteger r = new BigInteger(1, rBytes);
    BigInteger s = new BigInteger(1, sBytes);

    ASN1ObjectIdentifier oid;
    Digest digest;

    String header = new String(Base64.decodeUrl(jwtHeaderSegment));
    JSONObject headerO = new JSONObject(header);
    String jwtAlgStr = (String) headerO.get("alg");
    if ("ES256".equals(jwtAlgStr)) {
      oid = SECObjectIdentifiers.secp256r1;
      digest = new SHA256Digest();
    } else if ("ES384".equals(jwtAlgStr)) {
      oid = SECObjectIdentifiers.secp384r1;
      digest = new SHA384Digest();
    } else if ("ES512".equals(jwtAlgStr)) {
      oid = SECObjectIdentifiers.secp521r1;
      digest = new SHA512Digest();
    } else {
      throw new NoSuchAlgorithmException("JWT algorithm: " + jwtAlgStr);
    }

    X9ECParameters x9ECParameters = SECNamedCurves.getByOID(oid);

    ECDSASigner verifier = new ECDSASigner();
    BigInteger xB = new BigInteger(1, x);
    BigInteger yB = new BigInteger(1, y);
    ECCurve curve = x9ECParameters.getCurve();
    ECPoint qB = curve.createPoint(xB, yB, false);
    ECPoint q = new ECPoint.Fp(curve, qB.getX(), qB.getY());
    ECDomainParameters ecDomainParameters = new ECDomainParameters(curve, x9ECParameters.getG(), x9ECParameters.getN(),
        x9ECParameters.getH(), x9ECParameters.getSeed());
    ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(q, ecDomainParameters);
    verifier.init(false, ecPublicKeyParameters);
    String hp = jwtHeaderSegment + "." + jwtPayloadSegment;
    byte[] bytes = hp.getBytes("utf-8");
    digest.update(bytes, 0, bytes.length);
    byte[] out = new byte[digest.getDigestSize()];
    /* int result = */digest.doFinal(out, 0);

    boolean verified = verifier.verifySignature(out, r, s);
    return verified;
  }

  public String serialize(BigInteger D) throws NoSuchAlgorithmException, JSONException, InvalidKeyException,
      SignatureException, IOException, InvalidKeySpecException {

    ASN1ObjectIdentifier oid;
    Digest digest;
    String jwtAlgStr = (String) mHeader.get("alg");
    if ("ES256".equals(jwtAlgStr)) {
      oid = SECObjectIdentifiers.secp256r1;
      digest = new SHA256Digest();
    } else if ("ES384".equals(jwtAlgStr)) {
      oid = SECObjectIdentifiers.secp384r1;
      digest = new SHA384Digest();
    } else if ("ES512".equals(jwtAlgStr)) {
      oid = SECObjectIdentifiers.secp521r1;
      digest = new SHA512Digest();
    } else {
      throw new NoSuchAlgorithmException("JWT algorithm: " + jwtAlgStr);
    }

    X9ECParameters x9ECParameters = SECNamedCurves.getByOID(oid);
    ECDomainParameters ecParameterSpec = new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(),
        x9ECParameters.getN(), x9ECParameters.getH(), x9ECParameters.getSeed());
    ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(D, ecParameterSpec);

    String b64 = Base64.encodeBytes(mHeaderStr.getBytes("utf-8"), org.xmldap.util.Base64.DONT_BREAK_LINES
        | org.xmldap.util.Base64.URL);
    StringBuffer sb = new StringBuffer(b64);
    sb.append('.');
    b64 = Base64.encodeBytes(mJsonStr.getBytes("utf-8"), org.xmldap.util.Base64.DONT_BREAK_LINES
        | org.xmldap.util.Base64.URL);
    sb.append(b64);

    String stringToSign = sb.toString();
    byte[] bytes = stringToSign.getBytes("utf-8");
    digest.update(bytes, 0, bytes.length);
    byte[] out = new byte[digest.getDigestSize()];
    /* int result = */digest.doFinal(out, 0);

    sb.append('.');

    String signed = signECDSA(ecPrivateKeyParameters, out);

    sb.append(signed);
    return sb.toString();
  }

  private String signECDSA(ECPrivateKeyParameters ecPrivateKeyParameters, byte[] bytes)
      throws UnsupportedEncodingException {
    ECDSASigner signer = new ECDSASigner();
    signer.init(true, ecPrivateKeyParameters);
    BigInteger[] res = signer.generateSignature(bytes);
    BigInteger r = res[0];
    BigInteger s = res[1];

    String signed = rs2jwt(r, s);
    // System.out.println("Signed:" + signed);
    return signed;
  }

  // TODO FIXME let hashByteLen be a third parameter to replace the fixed 32
  private String rs2jwt(BigInteger r, BigInteger s) {
    // System.out.println("R:" + r.toString());
    // System.out.println("S:" + s.toString());
    byte[] rBytes = r.toByteArray();
    // System.out.println("rBytes.length:" + rBytes.length);
    byte[] sBytes = s.toByteArray();
    // System.out.println("sBytes.length:" + sBytes.length);
    // StringBuffer sb = new StringBuffer();
    // for (int i=0; i<rBytes.length;i++) {
    // sb.append(String.valueOf((int)rBytes[i]));
    // sb.append(',');
    // }
    // System.out.println("Rbytes:" + sb.toString());
    // sb = new StringBuffer();
    // for (int i=0; i<sBytes.length;i++) {
    // sb.append(String.valueOf((int)sBytes[i]));
    // sb.append(',');
    // }
    // System.out.println("Sbytes:" + sb.toString());
    byte[] rsBytes = new byte[64];
    for (int i = 0; i < rsBytes.length; i++) {
      rsBytes[i] = 0;
    }
    if (rBytes.length >= 32) {
      System.arraycopy(rBytes, rBytes.length - 32, rsBytes, 0, 32);
    } else {
      System.arraycopy(rBytes, 0, rsBytes, 32 - rBytes.length, rBytes.length);
    }
    if (sBytes.length >= 32) {
      System.arraycopy(sBytes, sBytes.length - 32, rsBytes, 32, 32);
    } else {
      System.arraycopy(sBytes, 0, rsBytes, 64 - sBytes.length, sBytes.length);
    }
    String signed = Base64.encodeBytes(rsBytes, org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
    return signed;
  }

  public String serialize(RSAPrivateKey privateKey) throws JSONException, NoSuchAlgorithmException,
      InvalidKeyException, SignatureException, IOException {
    String b64 = Base64.encodeBytes(mHeaderStr.getBytes("utf-8"), org.xmldap.util.Base64.DONT_BREAK_LINES
        | org.xmldap.util.Base64.URL);
    StringBuffer sb = new StringBuffer(b64);
    sb.append('.');
    b64 = Base64.encodeBytes(mJsonStr.getBytes("utf-8"), org.xmldap.util.Base64.DONT_BREAK_LINES
        | org.xmldap.util.Base64.URL);
    sb.append(b64);

    String stringToSign = sb.toString();

    sb.append('.');

    String jwtAlgStr = mHeader.getString("alg");
    Signature signature;
    String algorithm;
    if ("RS256".equals(jwtAlgStr)) {
      algorithm = "SHA256withRSA";
    } else if ("RS384".equals(jwtAlgStr)) {
      algorithm = "SHA384withRSA";
    } else if ("RS512".equals(jwtAlgStr)) {
      algorithm = "SHA512withRSA";
    } else {
      throw new NoSuchAlgorithmException("JWT algorithm: " + jwtAlgStr);
    }
    signature = Signature.getInstance(algorithm);
    signature.initSign(privateKey);
    signature.update(stringToSign.getBytes("utf-8"));
    byte[] bytes = signature.sign();

    b64 = Base64.encodeBytes(bytes, org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
    sb.append(b64);
    return sb.toString();
  }

  // public String serialize(PrivateKey privateKey)
  // throws UnsupportedEncodingException, JSONException,
  // NoSuchAlgorithmException, InvalidKeyException, SignatureException
  // {
  // String b64 = Base64.encodeBytes(mPKAlgorithm.getBytes("utf-8"),
  // org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
  // StringBuffer sb = new StringBuffer(b64);
  // sb.append('.');
  // b64 = Base64.encodeBytes(mJsonStr.getBytes("utf-8"),
  // org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
  // sb.append(b64);
  // sb.append('.');
  //
  // JSONObject algO = new JSONObject(mPKAlgorithm);
  // String jwtAlgStr = algO.getString("alg");
  //
  // Signature signature = Signature.getInstance(jwtAlgStr);
  // signature.initSign(privateKey);
  // signature.update(mJsonStr.getBytes("utf-8"));
  // byte[] bytes = signature.sign();
  // String signed = new String(bytes);
  // sb.append(signed);
  // return sb.toString();
  // }

  public static Mac getMac(String macAlgorithmName) throws NoSuchAlgorithmException {
    String jceName;
    if ("HS256".equals(macAlgorithmName)) { // HMAC SHA-256
      jceName = "HMACSHA256";
    } else if ("HS384".equals(macAlgorithmName)) { // HMAC SHA-384
      jceName = "HMACSHA384";
    } else if ("HS512".equals(macAlgorithmName)) { // HMAC SHA-512
      jceName = "HMACSHA512";
    } else {
      throw new NoSuchAlgorithmException(macAlgorithmName);
    }
    Mac mac = Mac.getInstance(jceName);
    return mac;
  }
  
  public static byte[] doMac(String macAlgorithmName, byte[] passphraseBytes, byte[] bytes) throws NoSuchAlgorithmException, InvalidKeyException {
    Mac mac = getMac(macAlgorithmName);
    mac.init(new SecretKeySpec(passphraseBytes, mac.getAlgorithm()));
    mac.update(bytes);
    return mac.doFinal();
  }
  
  public String serialize(byte[] passphraseBytes) throws JSONException, NoSuchAlgorithmException, InvalidKeyException,
      IllegalStateException, UnsupportedEncodingException {
    String b64 = Base64.encodeBytes(mHeaderStr.getBytes("utf-8"), org.xmldap.util.Base64.DONT_BREAK_LINES
        | org.xmldap.util.Base64.URL);
    StringBuffer sb = new StringBuffer(b64);
    sb.append('.');
    b64 = Base64.encodeBytes(mJsonStr.getBytes("utf-8"), org.xmldap.util.Base64.DONT_BREAK_LINES
        | org.xmldap.util.Base64.URL);
    sb.append(b64);

    String stringToSign = sb.toString();

    sb.append('.');
    String signed;

    String jwtAlgStr = mHeader.getString("alg");
    byte[] bytes = doMac(jwtAlgStr, passphraseBytes, stringToSign.getBytes());
    signed = Base64.encodeBytes(bytes, org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
    sb.append(signed);
    return sb.toString();
  }

//  public static String decrypt(String encrypted, String password) throws Exception {
//    String[] split = encrypted.split("\\.");
//    String headerB64 = split[0];
//    String jwtKeySegmentB64 = split[1];
//    String jwtCryptoSegmentB64 = split[2];
//
//    String jwtHeaderSegment = new String(Base64.decodeUrl(headerB64));
//    JSONObject jwtHeaderJSON = new JSONObject(jwtHeaderSegment);
//    String alg = jwtHeaderJSON.getString("alg");
//    if ("PE20".equals(alg)) {
//
//    }
//    String jwtKeySegment = new String(Base64.decodeUrl(jwtKeySegmentB64));
//    JSONObject jwtKeyJSON = new JSONObject(jwtKeySegment);
//    String wrappedKeyB64 = jwtKeyJSON.getString("wrp");
//    byte[] wrappedKey = Base64.decodeUrl(wrappedKeyB64);
//    String saltB64 = jwtKeyJSON.getString("slt");
//    byte[] salt = Base64.decodeUrl(saltB64);
//
//    final String algorithm = "PBEWithMD5AndDES";
//
//    PBEParameterSpec paramSpec = new PBEParameterSpec(salt, 20);
//    PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
//    SecretKeyFactory kf = SecretKeyFactory.getInstance(algorithm);
//    SecretKey passwordKey = kf.generateSecret(keySpec);
//
//    Cipher c = Cipher.getInstance("PBEWithMD5AndDES");
//
//    c.init(Cipher.UNWRAP_MODE, passwordKey, paramSpec);
//    Key unwrappedKey = c.unwrap(wrappedKey, "DESede", Cipher.SECRET_KEY);
//
//    c = Cipher.getInstance("DESede");
//    c.init(Cipher.DECRYPT_MODE, unwrappedKey);
//
//    byte[] jwtCryptoSegment = Base64.decodeUrl(jwtCryptoSegmentB64);
//    return new String(c.doFinal(jwtCryptoSegment));
//  }

  public String encrypt(SecretKey key, IvParameterSpec ivParamSpec) throws Exception {
    String b64 = Base64.encodeBytes(mHeaderStr.getBytes("utf-8"), org.xmldap.util.Base64.DONT_BREAK_LINES
        | org.xmldap.util.Base64.URL);
    StringBuffer sb = new StringBuffer(b64);
    sb.append('.');

    String alg = mHeader.getString("alg");
    if ((ENC_ALG_AE128.equals(alg)) || (ENC_ALG_AE192.equals(alg)) || (ENC_ALG_AE256.equals(alg))) {
      SafeObject keyBytes = new SafeObject();
      byte[] secretKey = key.getEncoded();
      keyBytes.setText(secretKey);

      StringBuffer clearTextBuffer = new StringBuffer(mJsonStr);
      String cipherText = CryptoUtils.encryptAESCBC(clearTextBuffer, keyBytes).toString();
      b64 = Base64.encodeBytes(cipherText.getBytes("utf-8"), org.xmldap.util.Base64.DONT_BREAK_LINES
          | org.xmldap.util.Base64.URL);
      sb.append(b64);
      // System.out.println("AES jwtCryptoSegment base64:" + b64);
    } else {
      if ((ENC_ALG_A128GCM.equals(alg)) || (ENC_ALG_A256GCM.equals(alg))) {
        b64 = Base64.encodeBytes(mHeaderStr.getBytes("utf-8"), org.xmldap.util.Base64.DONT_BREAK_LINES
            | org.xmldap.util.Base64.URL);
//        System.out.println("AESGCM jwtHeaderSegment base64:" + b64);
        sb = new StringBuffer(b64);
        sb.append('.');

        byte[] cipherbytes = CryptoUtils.aesgcmEncrypt(ivParamSpec, key, mJsonStr.getBytes("utf-8"));
        b64 = Base64.encodeBytes(cipherbytes, org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
        sb.append(b64);
//        System.out.println("AESGCM jwtCryptoSegment base64:" + b64);

      } else {
        throw new NoSuchAlgorithmException("unsupported JWT AES algorithm: " + alg);
      }
    }
    return sb.toString();

  }

  public static String decrypt(String encrypted, SecretKey key) throws Exception {
    String[] split = encrypted.split("\\.");
    String headerB64 = split[0];
    String jwtCryptoSegmentB64 = split[1];

    String jwtHeaderSegment = new String(Base64.decodeUrl(headerB64));

    String algorithm = key.getAlgorithm();
    if (!"AES".equals(algorithm)) {
      throw new NoSuchAlgorithmException("unsupported JWT AES algorithm: " + algorithm);
    }

    JSONObject header = new JSONObject(jwtHeaderSegment);
    String jwtAlgStr = (String) header.get("alg");
    if ((ENC_ALG_AE128.equals(jwtAlgStr)) || (ENC_ALG_AE192.equals(jwtAlgStr)) || (ENC_ALG_AE256.equals(jwtAlgStr))) {
      SafeObject keyBytes = new SafeObject();
      byte[] secretKey = key.getEncoded();
      keyBytes.setText(secretKey);

      byte[] jwtCryptoSegmentBytes = Base64.decodeUrl(jwtCryptoSegmentB64);
      StringBuffer clearTextBuffer = CryptoUtils.decryptAESCBC(new StringBuffer(new String(jwtCryptoSegmentBytes)),
          keyBytes);

      return clearTextBuffer.toString();
    } else if ((ENC_ALG_A128GCM.equals(jwtAlgStr)) || (ENC_ALG_A256GCM.equals(jwtAlgStr))) {
      String ivB64 = header.getString("iv");
      byte[] iv = Base64.decodeUrl(ivB64);
      IvParameterSpec ivParamSpec = new IvParameterSpec(iv);
      byte[] jwtCryptoSegmentBytes = Base64.decodeUrl(jwtCryptoSegmentB64);
      return new String(CryptoUtils.aesgcmDecrypt(ivParamSpec, key, jwtCryptoSegmentBytes));
    } else {
      throw new NoSuchAlgorithmException("unsupported keylength JWT AES algorithm: " + jwtAlgStr);
    }

  }

//  public String encrypt(String password) throws Exception {
//    final String algorithm = "PBEWithMD5AndDES";
//    String b64 = Base64.encodeBytes(mHeaderStr.getBytes("utf-8"), org.xmldap.util.Base64.DONT_BREAK_LINES
//        | org.xmldap.util.Base64.URL);
//    StringBuffer sb = new StringBuffer(b64);
//    sb.append('.');
//
//    KeyGenerator kg = KeyGenerator.getInstance("DESede");
//    Key sharedKey = kg.generateKey();
//
//    byte[] salt = new byte[8];
//    SecureRandom random = new SecureRandom();
//    random.nextBytes(salt);
//
//    PBEParameterSpec paramSpec = new PBEParameterSpec(salt, 20);
//    PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
//    SecretKeyFactory kf = SecretKeyFactory.getInstance(algorithm);
//    SecretKey passwordKey = kf.generateSecret(keySpec);
//    Cipher c = Cipher.getInstance(algorithm);
//    c.init(Cipher.WRAP_MODE, passwordKey, paramSpec);
//    byte[] wrappedKey = c.wrap(sharedKey);
//
//    JSONObject keyInfoO = new JSONObject();
//    b64 = Base64.encodeBytes(wrappedKey, org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
//    keyInfoO.put("wrp", b64);
//    b64 = Base64.encodeBytes(salt, org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
//    keyInfoO.put("slt", b64);
//    String keyInfoString = keyInfoO.toString();
//
//    b64 = Base64.encodeBytes(keyInfoString.getBytes("utf-8"), org.xmldap.util.Base64.DONT_BREAK_LINES
//        | org.xmldap.util.Base64.URL);
//    sb.append(b64);
//    sb.append('.');
//
//    c = Cipher.getInstance("DESede");
//    c.init(Cipher.ENCRYPT_MODE, sharedKey);
//    byte[] encrypted = c.doFinal(mJsonStr.getBytes());
//
//    b64 = Base64.encodeBytes(encrypted, org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
//    sb.append(b64);
//
//    return sb.toString();
//  }

  public static String decrypt(
      String encrypted, 
      ECPublicKeyParameters ecPublicKeyParameters, 
      ECPrivateKeyParameters ecPrivateKeyParameters,
      Digest kdfDigest) throws Exception 
  {
    String[] split = encrypted.split("\\.");
    String headerB64 = split[0];
    //String secretkeyB64 = split[1]; // empty string
    String jwtCryptoSegmentB64 = split[2];

    String jwtHeaderSegment = new String(Base64.decodeUrl(headerB64));
    JSONObject header = new JSONObject(jwtHeaderSegment);
    String jwtAlgStr = (String) header.get("alg");
    
    int keylength = 256;
    
    if (ENC_ALG_ECDH_ES.equals(jwtAlgStr)) {
      ECDHBasicAgreement ecdhBasicAgreement = new ECDHBasicAgreement();
      ecdhBasicAgreement.init(ecPrivateKeyParameters);
      BigInteger z = ecdhBasicAgreement.calculateAgreement(ecPublicKeyParameters);
//      System.out.println("ECDH-ES z=" + z.toString());
      byte[] zBytes = BigIntegers.asUnsignedByteArray(z);
      byte[] otherInfo = {69, 110, 99, 114, 121, 112, 116, 105, 111, 110};
      //      System.out.println("ECDH-ES zBytes.length=" + zBytes.length);
      KDFConcatGenerator kdfConcatGenerator = new KDFConcatGenerator(kdfDigest, otherInfo );
      kdfConcatGenerator.init(new KDFParameters(zBytes, null));
      byte[] secretKeyBytes = new byte[keylength / 8];
      kdfConcatGenerator.generateBytes(secretKeyBytes, 0, secretKeyBytes.length);
      SecretKey secretKey = new SecretKeySpec(secretKeyBytes, "AES");
      
      String ivBytesB64 = header.getString("iv");
      byte[] ivBytes = Base64.decodeUrl(ivBytesB64);
      IvParameterSpec ivParamSpec = new IvParameterSpec(ivBytes);
      
      byte[] jwtCryptoSegment = Base64.decodeUrl(jwtCryptoSegmentB64);
      byte[] cleartextBytes = CryptoUtils.aesgcmDecrypt(ivParamSpec, secretKey, jwtCryptoSegment);
      String cleartext = new String(cleartextBytes);
      return cleartext ;
    } else {
      throw new NoSuchAlgorithmException("JWT algorithm: " + jwtAlgStr);
    }
    
  }

  public String encrypt(ECPublicKeyParameters ecPublicKeyParameters, ECPrivateKeyParameters ecPrivateKeyParameters,
      Digest kdfDigest) throws Exception {
    int keylength;
    SecretKey contentEncryptionKey;
    String jwtEncStr = (String) mHeader.get("enc");

    if (ENC_ALG_A128GCM.equals(jwtEncStr)) {
      keylength = 128;
    } else {
      if (ENC_ALG_A256GCM.equals(jwtEncStr)) {
        keylength = 256;
      } else {
        throw new NoSuchAlgorithmException("JWT enc: " + jwtEncStr);
      }
    }

    String encodedJweCiphertext;
    String encodedJweEncryptedKey;

    String jwtAlgStr = (String) mHeader.get("alg");
    if (ENC_ALG_ECDH_ES.equals(jwtAlgStr)) {
      ECDHBasicAgreement ecdhBasicAgreement = new ECDHBasicAgreement();
      ecdhBasicAgreement.init(ecPrivateKeyParameters);
      BigInteger z = ecdhBasicAgreement.calculateAgreement(ecPublicKeyParameters);
//      System.out.println("ECDH-ES z=" + z.toString());
      byte[] zBytes = BigIntegers.asUnsignedByteArray(z);
//      System.out.println("ECDH-ES zBytes.length=" + zBytes.length);
      byte[] otherInfo = {69, 110, 99, 114, 121, 112, 116, 105, 111, 110};
      KDFConcatGenerator kdfConcatGenerator = new KDFConcatGenerator(kdfDigest, otherInfo);
      kdfConcatGenerator.init(new KDFParameters(zBytes, null));
      byte[] secretKeyBytes = new byte[keylength / 8];
      kdfConcatGenerator.generateBytes(secretKeyBytes, 0, secretKeyBytes.length);
      contentEncryptionKey = new SecretKeySpec(secretKeyBytes, "RAW");
      // encrypt the content encryption key using secretKey
      encodedJweEncryptedKey = "";
    } else {
      throw new NoSuchAlgorithmException("JWT algorithm: " + jwtAlgStr);
    }

    String headerStr = mHeaderStr;
    if ((ENC_ALG_A128GCM.equals(jwtEncStr)) || ((ENC_ALG_A256GCM.equals(jwtEncStr)))) {
      byte[] ivBytes;
      JSONObject header = new JSONObject(mHeaderStr);
      String ivStr = header.optString("iv", null);
      if (ivStr == null) {
        ivBytes = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(ivBytes);
        String b64 = Base64.encodeBytes(ivBytes, org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
        header.put("iv", b64);
        headerStr = header.toString();
      } else {
        ivBytes = Base64.decodeUrl(ivStr);
      }

      IvParameterSpec ivParamSpec = new IvParameterSpec(ivBytes);
      byte[] jweCypherText = CryptoUtils.aesgcmEncrypt(ivParamSpec, contentEncryptionKey, mJsonStr.getBytes("utf-8"));
      encodedJweCiphertext = Base64.encodeBytes(jweCypherText, org.xmldap.util.Base64.DONT_BREAK_LINES
          | org.xmldap.util.Base64.URL);
    } else {
      throw new NoSuchAlgorithmException("WebToken ECDH-ES encrypt: enc=" + jwtEncStr);
    }
    // System.out.println("jwtCryptoSegment base64:" + b64);

    String encodedJweHeader = Base64.encodeBytes(headerStr.getBytes("utf-8"), org.xmldap.util.Base64.DONT_BREAK_LINES
        | org.xmldap.util.Base64.URL);
    StringBuffer sb = new StringBuffer(encodedJweHeader);
    sb.append('.');
    sb.append(encodedJweEncryptedKey);
    sb.append('.');
    sb.append(encodedJweCiphertext);

    return sb.toString();
  }

  public static String decrypt(String encrypted, BigInteger x, BigInteger y, BigInteger D) throws Exception {
    String[] split = encrypted.split("\\.");
    String headerB64 = split[0];

    String jwtHeaderSegment = new String(Base64.decodeUrl(headerB64));

    JSONObject header = new JSONObject(jwtHeaderSegment);
    String jwtAlgStr = header.getString("alg");
    if (!"ECDH-ES".equals(jwtAlgStr)) {
      throw new NoSuchAlgorithmException("JWT algorithm: " + jwtAlgStr);
    }
    
    JSONObject epkJson = header.getJSONObject("epk");
    JSONArray jwkJSON = epkJson.getJSONArray("jwk");
    JSONObject keyJSON = jwkJSON.getJSONObject(0);
    String jwtCrvStr = keyJSON.getString("crv");
    Digest digest = new SHA256Digest();

    ASN1ObjectIdentifier oid = ECUtil.getNamedCurveOid(jwtCrvStr);
    if (oid == null) {
      throw new NoSuchAlgorithmException("JWT EC curve: " + jwtAlgStr);
    }
    
    X9ECParameters x9ECParameters = ECUtil.getNamedCurveByOid(oid);
    ECCurve curve = x9ECParameters.getCurve();
    ECPoint qB = curve.createPoint(x, y, false);
    ECPoint q = new ECPoint.Fp(curve, qB.getX(), qB.getY());
    ECDomainParameters ecDomainParameters = new ECDomainParameters(curve, x9ECParameters.getG(), x9ECParameters.getN(),
        x9ECParameters.getH(), x9ECParameters.getSeed());
    ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(q, ecDomainParameters);

    ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(D, ecDomainParameters);

    return decrypt(encrypted, ecPublicKeyParameters, ecPrivateKeyParameters, digest);
  }

  public String encrypt(BigInteger x, BigInteger y, BigInteger D) throws Exception {

    String jwtAlgStr = (String) mHeader.get("alg");
    ASN1ObjectIdentifier oid;
    Digest digest;
    if ("EE256".equals(jwtAlgStr) || ("ECDH-ES".equals(jwtAlgStr))) {
      oid = SECObjectIdentifiers.secp256r1;
      digest = new SHA256Digest();
    } else if ("EE384".equals(jwtAlgStr)) {
      oid = SECObjectIdentifiers.secp384r1;
      digest = new SHA384Digest();
    } else if ("EE512".equals(jwtAlgStr)) {
      oid = SECObjectIdentifiers.secp521r1;
      digest = new SHA512Digest();
    } else {
      throw new NoSuchAlgorithmException("JWT algorithm: " + jwtAlgStr);
    }
    X9ECParameters x9ECParameters = SECNamedCurves.getByOID(oid);
    ECCurve curve = x9ECParameters.getCurve();
    ECPoint qB = curve.createPoint(x, y, false);
    ECPoint q = new ECPoint.Fp(curve, qB.getX(), qB.getY());
    ECDomainParameters ecDomainParameters = new ECDomainParameters(curve, x9ECParameters.getG(), x9ECParameters.getN(),
        x9ECParameters.getH(), x9ECParameters.getSeed());
    ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(q, ecDomainParameters);

    ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(D, ecDomainParameters);

    return encrypt(ecPublicKeyParameters, ecPrivateKeyParameters, digest);
  }

  public String encrypt(RSAPublicKey rsaPublicKey) throws Exception {
    int keylength;
    String jwtEncStr = (String) mHeader.get("enc");
    if (ENC_ALG_A128CBC.equals(jwtEncStr)) {
      keylength = 128;
    } else if (ENC_ALG_A192CBC.equals(jwtEncStr)) {
      keylength = 192;
    } else if (ENC_ALG_A256CBC.equals(jwtEncStr)) {
      keylength = 256;
    } else if (ENC_ALG_A512CBC.equals(jwtEncStr)) {
      keylength = 512;
    } else if (ENC_ALG_A128GCM.equals(jwtEncStr)) {
      keylength = 128;
    } else if (ENC_ALG_A256GCM.equals(jwtEncStr)) {
      keylength = 256;
    } else {
      throw new NoSuchAlgorithmException("WebToken RSA encrypt: enc=" + jwtEncStr);
    }
    SecretKey contentEncryptionKey = CryptoUtils.genAesKey(keylength);
    return encrypt(rsaPublicKey, contentEncryptionKey);
  }

  public static byte[] generateCIK(byte[] keyBytes, int cikByteLength) {
    Digest kdfDigest = new SHA256Digest();
    // "Integrity"
    final byte[] otherInfo = { 73, 110, 116, 101, 103, 114, 105, 116, 121 };
    KDFConcatGenerator kdfConcatGenerator = new KDFConcatGenerator(kdfDigest, otherInfo);
    kdfConcatGenerator.init(new KDFParameters(keyBytes, null));
    byte[] key = new byte[cikByteLength];
    kdfConcatGenerator.generateBytes(key, 0, key.length);
    return key;
  }
  
  public static byte[] generateCEK(byte[] keyBytes, int cekByteLength) {
    Digest kdfDigest = new SHA256Digest();
    // "Encryption"
    final byte[] otherInfo = { 69, 110, 99, 114, 121, 112, 116, 105, 111, 110 };
    KDFConcatGenerator kdfConcatGenerator = new KDFConcatGenerator(kdfDigest, otherInfo);
    kdfConcatGenerator.init(new KDFParameters(keyBytes, null));
    byte[] key = new byte[cekByteLength];
    kdfConcatGenerator.generateBytes(key, 0, key.length);
    return key;
  }
  
  public String encrypt(RSAPublicKey rsaPublicKey, SecretKey contentEncryptionKey) throws Exception {
    String b64;
    String jwtEncStr = (String) mHeader.get("enc");
    
    String encodedJweCiphertext;
    String encodedJweEncryptedKey;
    String encodedJweIntegrityValue;
    
    String jwtAlgStr = (String) mHeader.get("alg");
    if (ENC_ALG_RSA1_5.equals(jwtAlgStr)) {
      Cipher encrypter = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      encrypter.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
      byte[] ciphertext = encrypter.doFinal(contentEncryptionKey.getEncoded());
      encodedJweEncryptedKey = Base64.encodeBytes(ciphertext, org.xmldap.util.Base64.DONT_BREAK_LINES
          | org.xmldap.util.Base64.URL);
    } else if (ENC_ALG_RSA_OAEP.equals(jwtAlgStr)) {
      byte[] cipheredKeyBytes = CryptoUtils.rsaoaepEncryptBytes(contentEncryptionKey.getEncoded(), rsaPublicKey);
      // System.out.print("ciphered keybytes\n[");
      // for (int i=0; i<(cipheredKeyBytes.length/8)-1; i++) {
      // System.out.print(Integer.toString(cipheredKeyBytes[i]) + ", ");
      // }
      // System.out.println(Integer.toString(cipheredKeyBytes[(cipheredKeyBytes.length/8)-1])
      // + "]");

      encodedJweEncryptedKey = Base64.encodeBytes(cipheredKeyBytes, org.xmldap.util.Base64.DONT_BREAK_LINES
          | org.xmldap.util.Base64.URL);
      // System.out.println("jwtSymmetricKeySegment base64:" + b64);
    } else {
      throw new NoSuchAlgorithmException("JWT algorithm: " + jwtAlgStr);
    }

    String headerStr = mHeaderStr;
    String encodedJweHeader = Base64.encodeBytes(headerStr.getBytes("utf-8"), org.xmldap.util.Base64.DONT_BREAK_LINES
        | org.xmldap.util.Base64.URL);

    if ((ENC_ALG_A128CBC.equals(jwtEncStr)) || ((ENC_ALG_A192CBC.equals(jwtEncStr)))
        || ((ENC_ALG_A256CBC.equals(jwtEncStr))) || ((ENC_ALG_A512CBC.equals(jwtEncStr)))) {
      byte[] cek = generateCEK(contentEncryptionKey.getEncoded(), 32);
      {
        SafeObject keyBytes = new SafeObject();
        keyBytes.setText(cek);
  
        StringBuffer clearTextBuffer = new StringBuffer(mJsonStr);
        String cipherText;
        try {
          cipherText = CryptoUtils.encryptAESCBC(clearTextBuffer, keyBytes).toString();
        } finally {
          keyBytes.clearText();
        }
        encodedJweCiphertext = Base64.encodeBytes(cipherText.getBytes("utf-8"), org.xmldap.util.Base64.DONT_BREAK_LINES
            | org.xmldap.util.Base64.URL);
        {
          String stringToSign = encodedJweHeader + "." + encodedJweEncryptedKey + "." + encodedJweCiphertext;
          byte[] cik = generateCIK(contentEncryptionKey.getEncoded(), 32);
          String jwtIntStr = (String) mHeader.get("int");
          byte[] bytes = doMac(jwtIntStr, cik, stringToSign.getBytes());
          encodedJweIntegrityValue = Base64.encodeBytes(bytes, org.xmldap.util.Base64.DONT_BREAK_LINES
            | org.xmldap.util.Base64.URL);
        }
      }
    } else if ((ENC_ALG_A128GCM.equals(jwtEncStr)) || ((ENC_ALG_A256GCM.equals(jwtEncStr)))) {
      byte[] ivBytes;
      JSONObject header = new JSONObject(mHeaderStr);
      String ivStr = header.optString("iv", null);
      if (ivStr == null) {
        ivBytes = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(ivBytes);
        b64 = Base64.encodeBytes(ivBytes, org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
        header.put("iv", b64);
        headerStr = header.toString();
        encodedJweHeader = Base64.encodeBytes(headerStr.getBytes("utf-8"), org.xmldap.util.Base64.DONT_BREAK_LINES
            | org.xmldap.util.Base64.URL);
      } else {
        ivBytes = Base64.decodeUrl(ivStr);
      }

      KeyParameter key = new KeyParameter(contentEncryptionKey.getEncoded());
      int macSizeBits = 128;
      byte[] nonce = ivBytes;
      String associatedText = encodedJweHeader.concat(".").concat(encodedJweEncryptedKey);
      byte[] associatedTextBytes = associatedText.getBytes();
      AEADParameters aeadParameters = new AEADParameters(key, macSizeBits, nonce, associatedTextBytes);

      String[] result = CryptoUtils.aesgcmEncrypt(aeadParameters, contentEncryptionKey, mJsonStr.getBytes("utf-8"));
      encodedJweCiphertext = result[0];
      encodedJweIntegrityValue = result[1];
    } else {
      throw new NoSuchAlgorithmException("WebToken RSA encrypt: enc=" + jwtEncStr);
    }
    // System.out.println("jwtCryptoSegment base64:" + b64);

    StringBuffer sb = new StringBuffer(encodedJweHeader);
    sb.append('.');
    sb.append(encodedJweEncryptedKey);
    sb.append('.');
    sb.append(encodedJweCiphertext);
    sb.append('.');
    sb.append(encodedJweIntegrityValue);

    return sb.toString();
  }

  public static String decrypt(String encrypted, RSAPrivateKey rsaPrivateKey) throws Exception {
    String[] split = encrypted.split("\\.");
    String encodedJwtHeaderSegment = split[0];
    String encodedJwtKeySegment = split[1];
    String encodedJwtCryptoSegment = split[2];
    String encodedJwtIntegritySegment = split[3];

    String jwtHeaderSegment = new String(Base64.decodeUrl(encodedJwtHeaderSegment));
    
    byte[] jwtIntegritySegmentBytes = Base64.decodeUrl(encodedJwtIntegritySegment);
    
    int keylength;
    String symmetricAlgorithm = "AES";
    JSONObject header = new JSONObject(jwtHeaderSegment);
    String jwtEncStr = (String) header.get("enc");
    if (ENC_ALG_A128CBC.equals(jwtEncStr)) {
      keylength = 128;
    } else if (ENC_ALG_A192CBC.equals(jwtEncStr)) {
      keylength = 192;
    } else if (ENC_ALG_A256CBC.equals(jwtEncStr)) {
      keylength = 256;
    } else if (ENC_ALG_A512CBC.equals(jwtEncStr)) {
      keylength = 512;
    } else if (ENC_ALG_A128GCM.equals(jwtEncStr)) {
      keylength = 128;
    } else if (ENC_ALG_A192GCM.equals(jwtEncStr)) {
      keylength = 192;
    } else if (ENC_ALG_A256GCM.equals(jwtEncStr)) {
      keylength = 256;
    } else if (ENC_ALG_A512GCM.equals(jwtEncStr)) {
      keylength = 512;
    } else {
      throw new NoSuchAlgorithmException("JWT algorithm: " + jwtEncStr);
    }

    byte[] cipheredKeyBytes = Base64.decodeUrl(encodedJwtKeySegment);

    SecretKeySpec keySpec;
    String jwtAlgStr = (String) header.get("alg");
    if (ENC_ALG_RSA1_5.equals(jwtAlgStr)) {
      Cipher encrypter = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      encrypter.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
      byte[] secretKeyBytes = encrypter.doFinal(cipheredKeyBytes);
      if (8 * secretKeyBytes.length != keylength) {
        throw new Exception("WebToken.decrypt RSA PKCS1Padding symmetric key length mismatch: " + secretKeyBytes.length
            + " != " + keylength);
      }
      keySpec = new SecretKeySpec(secretKeyBytes, symmetricAlgorithm);
    } else if (ENC_ALG_RSA_OAEP.equals(jwtAlgStr)) {
      byte[] secretKeyBytes = CryptoUtils.decryptRSAOAEP(cipheredKeyBytes, rsaPrivateKey);
      if (8 * secretKeyBytes.length != keylength) {
        throw new Exception("WebToken.decrypt RSA OAEP symmetric key length mismatch: " + secretKeyBytes.length
            + " != " + keylength);
      }
      keySpec = new SecretKeySpec(secretKeyBytes, symmetricAlgorithm);
    } else {
      throw new NoSuchAlgorithmException("RSA decrypt " + jwtAlgStr);
    }

    if ((ENC_ALG_A128CBC.equals(jwtEncStr)) || (ENC_ALG_A192CBC.equals(jwtEncStr))
        || (ENC_ALG_A256CBC.equals(jwtEncStr)) || (ENC_ALG_A512CBC.equals(jwtEncStr))) {
      byte[] cek = generateCEK(keySpec.getEncoded(), 32);

      SafeObject keyBytes = new SafeObject();
      byte[] secretKeyBytes = cek;
      keyBytes.setText(secretKeyBytes);

      byte[] jwtCryptoSegmentBytes = Base64.decodeUrl(encodedJwtCryptoSegment);
      StringBuffer clearTextBuffer = CryptoUtils.decryptAESCBC(new StringBuffer(new String(jwtCryptoSegmentBytes)),
          keyBytes);

      byte[] cik = generateCIK(keySpec.getEncoded(), 32);
      String stringToSign = encodedJwtHeaderSegment + "." + encodedJwtKeySegment + "." + encodedJwtCryptoSegment;
      String jwtIntStr = (String) header.get("int");
      byte[] bytes = doMac(jwtIntStr, cik, stringToSign.getBytes());
      if (Arrays.constantTimeAreEqual(bytes, jwtIntegritySegmentBytes)) {
        return clearTextBuffer.toString();
      } else {
        throw new Exception("jwt integrety check failed");
      }
    }
    if ((ENC_ALG_A128GCM.equals(jwtEncStr)) || (ENC_ALG_A192GCM.equals(jwtEncStr))
        || (ENC_ALG_A256GCM.equals(jwtEncStr)) || (ENC_ALG_A512GCM.equals(jwtEncStr))) {
      String ivB64 = header.getString("iv");
      byte[] ivBytes = Base64.decodeUrl(ivB64);
      KeyParameter key = new KeyParameter(keySpec.getEncoded());
      int macSizeBits = 128;
      
      byte[] nonce = ivBytes;
      String associatedText = encodedJwtHeaderSegment + "." + encodedJwtKeySegment;
      AEADParameters aeadParameters = new AEADParameters(key, macSizeBits, nonce, associatedText.getBytes());
      byte[] jwtCryptoSegmentBytes = Base64.decodeUrl(encodedJwtCryptoSegment);
      return new String(CryptoUtils.aesgcmDecrypt(aeadParameters, keySpec, jwtCryptoSegmentBytes, jwtIntegritySegmentBytes));
    } else {
      throw new NoSuchAlgorithmException("RSA AES decrypt " + jwtEncStr);
    }
  }
}
