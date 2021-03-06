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
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
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
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.xmldap.crypto.CryptoUtils;
import org.xmldap.crypto.KDFConcatGenerator;
import org.xmldap.exceptions.CryptoException;
import org.xmldap.util.Base64;

public class WebToken {

  public static final String SIGN_ALG_HS256 = "HS256";
  public static final String SIGN_ALG_HS384 = "HS384";
  public static final String SIGN_ALG_HS512 = "HS512";

  public static final String SIGN_ALG_ES256 = "ES256";
  public static final String SIGN_ALG_ES383 = "ES384";
  public static final String SIGN_ALG_ES512 = "ES512";

  public static final String SIGN_ALG_RS256 = "RS256";
  public static final String SIGN_ALG_RS383 = "RS384";
  public static final String SIGN_ALG_RS512 = "RS512";

  // RSA-OAEP encrypted AES-CBC key with 128 bits
  public static final String ENC_ALG_RE128 = "RE128";
  // RSA-OAEP encrypted AES-CBC key with 192 bits
  public static final String ENC_ALG_RE192 = "RE192";
  // RSA-OAEP encrypted AES-CBC key with 256 bits
  public static final String ENC_ALG_RE256 = "RE256";

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

  private WebToken() throws JSONException {
  }

  public static int getEncKeyLength(String jwtEncStr) throws JSONException, NoSuchAlgorithmException {
    int keylength;
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
    return keylength;
  }

  static int getIntKeyLength(String jwtIntStr) throws JSONException, NoSuchAlgorithmException {
    int keylength;
    if (WebToken.SIGN_ALG_HS256.equals(jwtIntStr)) {
      keylength = 256;
    } else if (WebToken.SIGN_ALG_HS384.equals(jwtIntStr)) {
      keylength = 384;
    } else if (WebToken.SIGN_ALG_HS512.equals(jwtIntStr)) {
      keylength = 512;
    } else {
      throw new NoSuchAlgorithmException("WebToken RSA encrypt: CBC inc=" + jwtIntStr);
    }
    return keylength;
  }

  static int getLargerKeylength(JSONObject jweHeader) throws NoSuchAlgorithmException, JSONException,
      IOException {
    String jwtEncStr = jweHeader.getString("enc");
    if (isAEADenc(jwtEncStr)) {
      // if there is an int then it is ignored
      return getEncKeyLength(jwtEncStr);
    }
    String jwtIntStr = jweHeader.getString("int");
    return Math.max(getEncKeyLength(jwtEncStr), getIntKeyLength(jwtIntStr));
  }

  static boolean isAEADenc(String jwtEncStr) throws NoSuchAlgorithmException, JSONException {
    if (ENC_ALG_A128CBC.equals(jwtEncStr)) {
      return false;
    } else if (ENC_ALG_A192CBC.equals(jwtEncStr)) {
      return false;
    } else if (ENC_ALG_A256CBC.equals(jwtEncStr)) {
      return false;
    } else if (ENC_ALG_A512CBC.equals(jwtEncStr)) {
      return false;
    } else if (ENC_ALG_A128GCM.equals(jwtEncStr)) {
      return true;
    } else if (ENC_ALG_A256GCM.equals(jwtEncStr)) {
      return true;
    } else {
      throw new NoSuchAlgorithmException("WebToken RSA encrypt: enc=" + jwtEncStr);
    }
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

  static String serialize(byte[] contentToSign, JSONObject jwsHeader, BigInteger D) throws NoSuchAlgorithmException,
      JSONException, InvalidKeyException, SignatureException, IOException, InvalidKeySpecException {

    ASN1ObjectIdentifier oid;
    Digest digest;
    String jwtAlgStr = jwsHeader.getString("alg");
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

    String b64 = Base64.encodeBytes(jwsHeader.toString().getBytes("utf-8"), org.xmldap.util.Base64.DONT_BREAK_LINES
        | org.xmldap.util.Base64.URL);
    StringBuffer sb = new StringBuffer(b64);
    sb.append('.');
    b64 = Base64.encodeBytes(contentToSign, org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
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

  private static String signECDSA(ECPrivateKeyParameters ecPrivateKeyParameters, byte[] bytes)
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
  private static String rs2jwt(BigInteger r, BigInteger s) {
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

  static String serialize(byte[] contentToSign, JSONObject jwsHeader, RSAPrivateKey privateKey) throws JSONException,
      NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
    String b64 = Base64.encodeBytes(jwsHeader.toString().getBytes("utf-8"), org.xmldap.util.Base64.DONT_BREAK_LINES
        | org.xmldap.util.Base64.URL);
    StringBuffer sb = new StringBuffer(b64);
    sb.append('.');
    b64 = Base64.encodeBytes(contentToSign, org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
    sb.append(b64);

    String stringToSign = sb.toString();

    sb.append('.');

    String jwtAlgStr = jwsHeader.getString("alg");
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

  public static byte[] doMac(String macAlgorithmName, byte[] passphraseBytes, byte[] bytes)
      throws NoSuchAlgorithmException, InvalidKeyException {
    Mac mac = getMac(macAlgorithmName);
    mac.init(new SecretKeySpec(passphraseBytes, mac.getAlgorithm()));
    mac.update(bytes);
    return mac.doFinal();
  }

  static String serialize(byte[] contentToSign, String jwsHeaderStr, byte[] passphraseBytes) throws JSONException,
      NoSuchAlgorithmException, InvalidKeyException, IllegalStateException, UnsupportedEncodingException {
    String b64 = Base64.encodeBytes(jwsHeaderStr.getBytes(), org.xmldap.util.Base64.DONT_BREAK_LINES
        | org.xmldap.util.Base64.URL);
    StringBuffer sb = new StringBuffer(b64);
    sb.append('.');
    b64 = Base64.encodeBytes(contentToSign, org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
    sb.append(b64);

    String stringToSign = sb.toString();

    sb.append('.');
    String signed;

    JSONObject jwsHeader = new JSONObject(jwsHeaderStr);
    String jwtAlgStr = jwsHeader.getString("alg");
    byte[] bytes = doMac(jwtAlgStr, passphraseBytes, stringToSign.getBytes());
    signed = Base64.encodeBytes(bytes, org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
    sb.append(signed);
    return sb.toString();
  }

  // public static String decrypt(String encrypted, String password) throws
  // Exception {
  // String[] split = encrypted.split("\\.");
  // String headerB64 = split[0];
  // String jwtKeySegmentB64 = split[1];
  // String jwtCryptoSegmentB64 = split[2];
  //
  // String jwtHeaderSegment = new String(Base64.decodeUrl(headerB64));
  // JSONObject jwtHeaderJSON = new JSONObject(jwtHeaderSegment);
  // String alg = jwtHeaderJSON.getString("alg");
  // if ("PE20".equals(alg)) {
  //
  // }
  // String jwtKeySegment = new String(Base64.decodeUrl(jwtKeySegmentB64));
  // JSONObject jwtKeyJSON = new JSONObject(jwtKeySegment);
  // String wrappedKeyB64 = jwtKeyJSON.getString("wrp");
  // byte[] wrappedKey = Base64.decodeUrl(wrappedKeyB64);
  // String saltB64 = jwtKeyJSON.getString("slt");
  // byte[] salt = Base64.decodeUrl(saltB64);
  //
  // final String algorithm = "PBEWithMD5AndDES";
  //
  // PBEParameterSpec paramSpec = new PBEParameterSpec(salt, 20);
  // PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
  // SecretKeyFactory kf = SecretKeyFactory.getInstance(algorithm);
  // SecretKey passwordKey = kf.generateSecret(keySpec);
  //
  // Cipher c = Cipher.getInstance("PBEWithMD5AndDES");
  //
  // c.init(Cipher.UNWRAP_MODE, passwordKey, paramSpec);
  // Key unwrappedKey = c.unwrap(wrappedKey, "DESede", Cipher.SECRET_KEY);
  //
  // c = Cipher.getInstance("DESede");
  // c.init(Cipher.DECRYPT_MODE, unwrappedKey);
  //
  // byte[] jwtCryptoSegment = Base64.decodeUrl(jwtCryptoSegmentB64);
  // return new String(c.doFinal(jwtCryptoSegment));
  // }

  static String encrypt(byte[] contentBytes, String jweHeaderStr, SecretKey key) throws Exception {
    SecureRandom sr = new SecureRandom();
    return encrypt(contentBytes, jweHeaderStr, key, sr);
  }

  static String encrypt(byte[] contentBytes, String jweHeaderStr, SecretKey key, SecureRandom sr) throws Exception {
    byte[] cmk;
    JSONObject jweHeader = new JSONObject(jweHeaderStr);
    String alg = jweHeader.getString("alg");
    String jwtEncStr = jweHeader.getString("enc");
    if ((ENC_ALG_A128KW.equals(alg)) || (ENC_ALG_A256KW.equals(alg))) {
      // AES key wrap
      // generate random cmk
      int keyLengthInBits = WebToken.getLargerKeylength(jweHeader);
      cmk = new byte[keyLengthInBits / 8];
      sr.nextBytes(cmk);
    } else {
      throw new Exception("alg not supported: " + alg);
    }
    SecretKeySpec contentEncryptionKey = new SecretKeySpec(cmk, "AES");

    byte[] wrappedKey = CryptoUtils.wrapAesKey(contentEncryptionKey, key);
    String encodedJweEncryptedKey = Base64.encodeBytes(wrappedKey, org.xmldap.util.Base64.DONT_BREAK_LINES
        | org.xmldap.util.Base64.URL);

    if ((ENC_ALG_A128CBC.equals(jwtEncStr)) || ((ENC_ALG_A192CBC.equals(jwtEncStr)))
        || ((ENC_ALG_A256CBC.equals(jwtEncStr))) || ((ENC_ALG_A512CBC.equals(jwtEncStr)))) {
      return encryptAesCbc(contentBytes, jweHeaderStr, contentEncryptionKey, jwtEncStr, encodedJweEncryptedKey);
    } else if ((ENC_ALG_A128GCM.equals(jwtEncStr)) || ((ENC_ALG_A256GCM.equals(jwtEncStr)))) {
      return encryptAesGcm(contentBytes, jweHeaderStr, contentEncryptionKey, encodedJweEncryptedKey);
    } else {
      throw new NoSuchAlgorithmException("WebToken RSA encrypt: enc=" + jwtEncStr);
    }

  }

  public static byte[] decrypt(String encrypted, SecretKey key) throws Exception {
    String[] split = encrypted.split("\\.");
    String encodedJwtHeaderSegment = split[0];
    String encodedJwtKeySegment = split[1];
    String encodedJwtCryptoSegment = split[2];
    String encodedjwtIntegritySegment = split[3];
    byte[] jwtIntegritySegmentBytes = Base64.decodeUrl(encodedjwtIntegritySegment);

    String jwtHeaderSegment = new String(Base64.decodeUrl(encodedJwtHeaderSegment));

    JSONObject header = new JSONObject(jwtHeaderSegment);
    String jwtAlgStr = (String) header.get("alg");
    byte[] secretKeyBytes;
    if ((ENC_ALG_A128KW.equals(jwtAlgStr)) || (ENC_ALG_A256KW.equals(jwtAlgStr))) {
      byte[] keyToBeUnwrapped = Base64.decodeUrl(encodedJwtKeySegment);
      Key cmk = CryptoUtils.unwrapAesKey(keyToBeUnwrapped, key);
      secretKeyBytes = cmk.getEncoded();
    } else {
      throw new Exception("alg not supported: " + jwtAlgStr);
    }

    return doDecrypt(encodedJwtHeaderSegment, encodedJwtKeySegment, encodedJwtCryptoSegment, jwtIntegritySegmentBytes,
        header, secretKeyBytes);

  }

  // public String encrypt(String password) throws Exception {
  // final String algorithm = "PBEWithMD5AndDES";
  // String b64 = Base64.encodeBytes(mHeaderStr.getBytes("utf-8"),
  // org.xmldap.util.Base64.DONT_BREAK_LINES
  // | org.xmldap.util.Base64.URL);
  // StringBuffer sb = new StringBuffer(b64);
  // sb.append('.');
  //
  // KeyGenerator kg = KeyGenerator.getInstance("DESede");
  // Key sharedKey = kg.generateKey();
  //
  // byte[] salt = new byte[8];
  // SecureRandom random = new SecureRandom();
  // random.nextBytes(salt);
  //
  // PBEParameterSpec paramSpec = new PBEParameterSpec(salt, 20);
  // PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
  // SecretKeyFactory kf = SecretKeyFactory.getInstance(algorithm);
  // SecretKey passwordKey = kf.generateSecret(keySpec);
  // Cipher c = Cipher.getInstance(algorithm);
  // c.init(Cipher.WRAP_MODE, passwordKey, paramSpec);
  // byte[] wrappedKey = c.wrap(sharedKey);
  //
  // JSONObject keyInfoO = new JSONObject();
  // b64 = Base64.encodeBytes(wrappedKey,
  // org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
  // keyInfoO.put("wrp", b64);
  // b64 = Base64.encodeBytes(salt, org.xmldap.util.Base64.DONT_BREAK_LINES |
  // org.xmldap.util.Base64.URL);
  // keyInfoO.put("slt", b64);
  // String keyInfoString = keyInfoO.toString();
  //
  // b64 = Base64.encodeBytes(keyInfoString.getBytes("utf-8"),
  // org.xmldap.util.Base64.DONT_BREAK_LINES
  // | org.xmldap.util.Base64.URL);
  // sb.append(b64);
  // sb.append('.');
  //
  // c = Cipher.getInstance("DESede");
  // c.init(Cipher.ENCRYPT_MODE, sharedKey);
  // byte[] encrypted = c.doFinal(mJsonStr.getBytes());
  //
  // b64 = Base64.encodeBytes(encrypted, org.xmldap.util.Base64.DONT_BREAK_LINES
  // | org.xmldap.util.Base64.URL);
  // sb.append(b64);
  //
  // return sb.toString();
  // }

  public static byte[] decrypt(String encrypted, ECPublicKeyParameters ecPublicKeyParameters,
      ECPrivateKeyParameters ecPrivateKeyParameters, Digest kdfDigest) throws Exception {
    String[] split = encrypted.split("\\.");
    String encodedJwtHeaderSegment = split[0];
    String encodedJwtKeySegment = split[1];
    String encodedJwtCryptoSegment = split[2];
    String encodedJwtIntegritySegment = split[3];
    byte[] jwtIntegritySegmentBytes = Base64.decodeUrl(encodedJwtIntegritySegment);

    String jwtHeaderSegment = new String(Base64.decodeUrl(encodedJwtHeaderSegment));
    JSONObject header = new JSONObject(jwtHeaderSegment);
    String jwtAlgStr = (String) header.get("alg");

    int keylength = 256;

    byte[] secretKeyBytes;
    if (ENC_ALG_ECDH_ES.equals(jwtAlgStr)) {
      ECDHBasicAgreement ecdhBasicAgreement = new ECDHBasicAgreement();
      ecdhBasicAgreement.init(ecPrivateKeyParameters);
      BigInteger z = ecdhBasicAgreement.calculateAgreement(ecPublicKeyParameters);
      // System.out.println("ECDH-ES z=" + z.toString());
      byte[] zBytes = BigIntegers.asUnsignedByteArray(z);
      byte[] otherInfo = { 69, 110, 99, 114, 121, 112, 116, 105, 111, 110 };
      // System.out.println("ECDH-ES zBytes.length=" + zBytes.length);
      KDFConcatGenerator kdfConcatGenerator = new KDFConcatGenerator(kdfDigest, otherInfo);
      kdfConcatGenerator.init(new KDFParameters(zBytes, null));
      secretKeyBytes = new byte[keylength / 8];
      kdfConcatGenerator.generateBytes(secretKeyBytes, 0, secretKeyBytes.length);
    } else {
      throw new NoSuchAlgorithmException("JWT algorithm: " + jwtAlgStr);
    }

    return doDecrypt(encodedJwtHeaderSegment, encodedJwtKeySegment, encodedJwtCryptoSegment, jwtIntegritySegmentBytes,
        header, secretKeyBytes);

  }

  private static byte[] doJwtDecrypt(String encodedJwtHeaderSegment, String encodedJwtKeySegment,
      String encodedJwtCryptoSegment, byte[] jwtIntegritySegmentBytes, JSONObject header, byte[] secretKeyBytes)
      throws NoSuchAlgorithmException, JSONException, NoSuchPaddingException, Exception, InvalidKeyException,
      InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidCipherTextException {
    String jwtEncStr = header.getString("enc");
    byte[] jwtCryptoSegmentBytes = Base64.decodeUrl(encodedJwtCryptoSegment);

    if ((ENC_ALG_A128CBC.equals(jwtEncStr)) || ((ENC_ALG_A192CBC.equals(jwtEncStr)))
        || ((ENC_ALG_A256CBC.equals(jwtEncStr))) || ((ENC_ALG_A512CBC.equals(jwtEncStr)))) {

      int cekLength = WebToken.enc2cekLength(header.getString("enc"));
      byte[] cek = WebToken.generateCEK(secretKeyBytes, cekLength);

      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      String ivStr = header.getString("iv");
      byte[] ivBytes = Base64.decodeUrl(ivStr);
      IvParameterSpec ivParameter = new IvParameterSpec(ivBytes);
      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cek, "AES"), ivParameter);
      byte[] jwtCrytoSegmentBytes = Base64.decodeUrl(encodedJwtCryptoSegment);
      byte[] cleartextBytes = cipher.doFinal(jwtCrytoSegmentBytes);

      String jwtIntStr = header.getString("int");
      int cikLength = WebToken.int2cikLength(jwtIntStr);
      byte[] cik = WebToken.generateCIK(secretKeyBytes, cikLength);
      String stringToSign = encodedJwtHeaderSegment + "." + encodedJwtKeySegment + "." + encodedJwtCryptoSegment;
      byte[] bytes = WebToken.doMac(jwtIntStr, cik, stringToSign.getBytes());

      if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(bytes, jwtIntegritySegmentBytes)) {
        throw new Exception("integrity check failed");
      }

      return cleartextBytes;
    } else if ((ENC_ALG_A128GCM.equals(jwtEncStr)) || (ENC_ALG_A192GCM.equals(jwtEncStr))
        || (ENC_ALG_A256GCM.equals(jwtEncStr)) || (ENC_ALG_A512GCM.equals(jwtEncStr))) {
      String ivB64 = header.getString("iv");
      byte[] ivBytes = Base64.decodeUrl(ivB64);
      KeyParameter key = new KeyParameter(secretKeyBytes);
      int macSizeBits = 128;

      byte[] nonce = ivBytes;
      String associatedText = encodedJwtHeaderSegment + "." + encodedJwtKeySegment;
      AEADParameters aeadParameters = new AEADParameters(key, macSizeBits, nonce, associatedText.getBytes());
      SecretKeySpec keySpec = new SecretKeySpec(secretKeyBytes, "AES");
      return CryptoUtils.aesgcmDecrypt(aeadParameters, keySpec, jwtCryptoSegmentBytes, jwtIntegritySegmentBytes);
    } else {
      throw new NoSuchAlgorithmException("RSA AES decrypt " + jwtEncStr);
    }
  }

  private static byte[] doDecrypt(String encodedJwtHeaderSegment, String encodedJwtKeySegment,
      String encodedJwtCryptoSegment, byte[] jwtIntegritySegmentBytes, JSONObject header, byte[] secretKeyBytes)
      throws JSONException, NoSuchAlgorithmException, Exception, CryptoException, InvalidKeyException,
      InvalidCipherTextException {
    String jwtEncStr = (String) header.get("enc");
    if ((ENC_ALG_A128CBC.equals(jwtEncStr)) || (ENC_ALG_A192CBC.equals(jwtEncStr))
        || (ENC_ALG_A256CBC.equals(jwtEncStr)) || (ENC_ALG_A512CBC.equals(jwtEncStr))) {
      int cekLength = enc2cekLength(jwtEncStr);
      byte[] cek = generateCEK(secretKeyBytes, cekLength);

      System.out.println("base64 CEK="
          + Base64.encodeBytes(cek, org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL));

      // byte[] jwtCryptoSegmentBytes =
      // Base64.decodeUrl(encodedJwtCryptoSegment);
      // byte[] cleartext = CryptoUtils.decryptAESCBC(jwtCryptoSegmentBytes,
      // cek);
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      String ivStr = header.getString("iv");
      byte[] ivBytes = Base64.decodeUrl(ivStr);
      IvParameterSpec ivParameter = new IvParameterSpec(ivBytes);
      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cek, "AES"), ivParameter);
      byte[] jwtCrytoSegmentBytes = Base64.decodeUrl(encodedJwtCryptoSegment);
      byte[] cleartextBytes = cipher.doFinal(jwtCrytoSegmentBytes);

      String jwtIntStr = (String) header.get("int");
      int cikLength = int2cikLength(jwtIntStr);
      byte[] cik = generateCIK(secretKeyBytes, cikLength);
      String stringToSign = encodedJwtHeaderSegment + "." + encodedJwtKeySegment + "." + encodedJwtCryptoSegment;
      byte[] bytes = doMac(jwtIntStr, cik, stringToSign.getBytes());
      if (Arrays.constantTimeAreEqual(bytes, jwtIntegritySegmentBytes)) {
        return cleartextBytes;
      } else {
        throw new Exception("jwt integrity check failed");
      }
    } else if ((ENC_ALG_A128GCM.equals(jwtEncStr)) || (ENC_ALG_A192GCM.equals(jwtEncStr))
        || (ENC_ALG_A256GCM.equals(jwtEncStr)) || (ENC_ALG_A512GCM.equals(jwtEncStr))) {
      String ivB64 = header.getString("iv");
      byte[] ivBytes = Base64.decodeUrl(ivB64);
      KeyParameter key = new KeyParameter(secretKeyBytes);
      int macSizeBits = 128;

      byte[] nonce = ivBytes;
      String associatedText = encodedJwtHeaderSegment + "." + encodedJwtKeySegment;
      AEADParameters aeadParameters = new AEADParameters(key, macSizeBits, nonce, associatedText.getBytes());
      byte[] jwtCryptoSegmentBytes = Base64.decodeUrl(encodedJwtCryptoSegment);
      SecretKeySpec sks = new SecretKeySpec(secretKeyBytes, "AES");
      return CryptoUtils.aesgcmDecrypt(aeadParameters, sks, jwtCryptoSegmentBytes, jwtIntegritySegmentBytes);
    } else {
      throw new NoSuchAlgorithmException("RSA AES decrypt " + jwtEncStr);
    }
  }

  static String encrypt(byte[] contentBytes, String jweHeaderStr, ECPublicKeyParameters ecPublicKeyParameters,
      ECPrivateKeyParameters ecPrivateKeyParameters, Digest kdfDigest) throws Exception {
    int keylength;
    SecretKey contentEncryptionKey;
    JSONObject jweHeader = new JSONObject(jweHeaderStr);
    String jwtEncStr = (String) jweHeader.get("enc");

    if (ENC_ALG_A128GCM.equals(jwtEncStr)) {
      keylength = 128;
    } else {
      if (ENC_ALG_A256GCM.equals(jwtEncStr)) {
        keylength = 256;
      } else {
        throw new NoSuchAlgorithmException("JWT enc: " + jwtEncStr);
      }
    }

    String encodedJweEncryptedKey;

    String jwtAlgStr = (String) jweHeader.get("alg");
    if (ENC_ALG_ECDH_ES.equals(jwtAlgStr)) {
      ECDHBasicAgreement ecdhBasicAgreement = new ECDHBasicAgreement();
      ecdhBasicAgreement.init(ecPrivateKeyParameters);
      BigInteger z = ecdhBasicAgreement.calculateAgreement(ecPublicKeyParameters);
      // System.out.println("ECDH-ES z=" + z.toString());
      byte[] zBytes = BigIntegers.asUnsignedByteArray(z);
      // System.out.println("ECDH-ES zBytes.length=" + zBytes.length);
      byte[] otherInfo = { 69, 110, 99, 114, 121, 112, 116, 105, 111, 110 };
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

    if ((ENC_ALG_A128CBC.equals(jwtEncStr)) || ((ENC_ALG_A192CBC.equals(jwtEncStr)))
        || ((ENC_ALG_A256CBC.equals(jwtEncStr))) || ((ENC_ALG_A512CBC.equals(jwtEncStr)))) {
      return encryptAesCbc(contentBytes, jweHeaderStr, contentEncryptionKey, jwtEncStr, encodedJweEncryptedKey);
    } else if ((ENC_ALG_A128GCM.equals(jwtEncStr)) || ((ENC_ALG_A256GCM.equals(jwtEncStr)))) {
      return encryptAesGcm(contentBytes, jweHeaderStr, contentEncryptionKey, encodedJweEncryptedKey);
    } else {
      throw new NoSuchAlgorithmException("WebToken RSA encrypt: enc=" + jwtEncStr);
    }
  }

  static ASN1ObjectIdentifier getNamedCurveOid(String jwtCrvStr) {
    if ("P-256".equals(jwtCrvStr) || "secp256r1".equals(jwtCrvStr)) {
      return SECObjectIdentifiers.secp256r1;
    } else if ("P-384".equals(jwtCrvStr) || "secp384r1".equals(jwtCrvStr)) {
      return SECObjectIdentifiers.secp384r1;
    } else if ("P-521".equals(jwtCrvStr) || "secp521r1".equals(jwtCrvStr)) {
      return SECObjectIdentifiers.secp521r1;
    } else {
      return null;
    }
  }

  public static byte[] decrypt(String encrypted, BigInteger x, BigInteger y, BigInteger D) throws Exception {
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

    ASN1ObjectIdentifier oid = getNamedCurveOid(jwtCrvStr);
    if (oid == null) {
      throw new NoSuchAlgorithmException("JWT EC curve: " + jwtCrvStr);
    }

    X9ECParameters x9ECParameters = SECNamedCurves.getByOID(oid);
    ECCurve curve = x9ECParameters.getCurve();
    ECPoint qB = curve.createPoint(x, y, false);
    ECPoint q = new ECPoint.Fp(curve, qB.getX(), qB.getY());
    ECDomainParameters ecDomainParameters = new ECDomainParameters(curve, x9ECParameters.getG(), x9ECParameters.getN(),
        x9ECParameters.getH(), x9ECParameters.getSeed());
    ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(q, ecDomainParameters);

    ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(D, ecDomainParameters);

    return decrypt(encrypted, ecPublicKeyParameters, ecPrivateKeyParameters, digest);
  }

  static String encrypt(byte[] contentBytes, String jweHeaderStr, BigInteger x, BigInteger y, BigInteger D) throws Exception {

    JSONObject jweHeader = new JSONObject(jweHeaderStr);
    String jwtAlgStr = jweHeader.getString("alg");
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

    return encrypt(contentBytes, jweHeaderStr, ecPublicKeyParameters, ecPrivateKeyParameters, digest);
  }

  static String encrypt(byte[]contentBytes, String jwtHeaderStr, RSAPublicKey rsaPublicKey) throws Exception {
    int keylength;
    JSONObject jweHeader = new JSONObject(jwtHeaderStr);
    String jwtEncStr = jweHeader.getString("enc");
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
    return encrypt(contentBytes, jwtHeaderStr, rsaPublicKey, contentEncryptionKey);
  }

  private static byte[] generateCIK(byte[] keyBytes, int cikByteLength) {
    Digest kdfDigest = new SHA256Digest();
    // "Integrity"
    final byte[] otherInfo = { 73, 110, 116, 101, 103, 114, 105, 116, 121 };
    KDFConcatGenerator kdfConcatGenerator = new KDFConcatGenerator(kdfDigest, otherInfo);
    kdfConcatGenerator.init(new KDFParameters(keyBytes, null));
    byte[] key = new byte[cikByteLength];
    kdfConcatGenerator.generateBytes(key, 0, key.length);
    return key;
  }

  private static byte[] generateCEK(byte[] keyBytes, int cekByteLength) {
    Digest kdfDigest = new SHA256Digest();
    // "Encryption"
    final byte[] otherInfo = { 69, 110, 99, 114, 121, 112, 116, 105, 111, 110 };
    KDFConcatGenerator kdfConcatGenerator = new KDFConcatGenerator(kdfDigest, otherInfo);
    kdfConcatGenerator.init(new KDFParameters(keyBytes, null));
    byte[] key = new byte[cekByteLength];
    kdfConcatGenerator.generateBytes(key, 0, key.length);
    return key;
  }

  public static int enc2cekLength(String jwtEncStr) throws NoSuchAlgorithmException {
    int cekLength;
    {
      if (ENC_ALG_A128CBC.equals(jwtEncStr)) {
        cekLength = 128 / 8;
      } else if (ENC_ALG_A192CBC.equals(jwtEncStr)) {
        cekLength = 192 / 8;
      } else if (ENC_ALG_A256CBC.equals(jwtEncStr)) {
        cekLength = 256 / 8;
      } else if (ENC_ALG_A512CBC.equals(jwtEncStr)) {
        cekLength = 512 / 8;
      } else {
        throw new NoSuchAlgorithmException("WebToken RSA encrypt: CBC enc=" + jwtEncStr);
      }
    }
    return cekLength;
  }

  public static int int2cikLength(String jwtIntStr) throws NoSuchAlgorithmException {
    int cikLength;
    if (SIGN_ALG_HS256.equals(jwtIntStr)) {
      cikLength = 256 / 8;
    } else if (SIGN_ALG_HS384.equals(jwtIntStr)) {
      cikLength = 384 / 8;
    } else if (SIGN_ALG_HS512.equals(jwtIntStr)) {
      cikLength = 512 / 8;
    } else {
      throw new NoSuchAlgorithmException("WebToken RSA encrypt: CBC inc=" + jwtIntStr);
    }
    return cikLength;
  }

  static String encrypt(byte[] contentBytes, String jweHeaderStr, RSAPublicKey rsaPublicKey, SecretKey contentEncryptionKey)
      throws Exception {
    JSONObject jweHeader = new JSONObject(jweHeaderStr);
    String jwtEncStr = jweHeader.getString("enc");

    String encodedJweEncryptedKey;

    String jwtAlgStr = jweHeader.getString("alg");
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

    if ((ENC_ALG_A128CBC.equals(jwtEncStr)) || ((ENC_ALG_A192CBC.equals(jwtEncStr)))
        || ((ENC_ALG_A256CBC.equals(jwtEncStr))) || ((ENC_ALG_A512CBC.equals(jwtEncStr)))) {
      return encryptAesCbc(contentBytes, jweHeaderStr, contentEncryptionKey, jwtEncStr, encodedJweEncryptedKey);
    } else if ((ENC_ALG_A128GCM.equals(jwtEncStr)) || ((ENC_ALG_A256GCM.equals(jwtEncStr)))) {
      return encryptAesGcm(contentBytes, jweHeaderStr, contentEncryptionKey, encodedJweEncryptedKey);
    } else {
      throw new NoSuchAlgorithmException("WebToken RSA encrypt: enc=" + jwtEncStr);
    }
    // System.out.println("jwtCryptoSegment base64:" + b64);

  }

  private static String encryptAesCbc(byte[] contentBytes, String jweHeaderStr, SecretKey contentEncryptionKey, String jwtEncStr,
      String encodedJweEncryptedKey) throws Exception {
    JSONObject jweHeader = new JSONObject(jweHeaderStr);
    byte[] iv;
    JSONObject header;
    String headerStr;
    if (jweHeader.has("iv")) {
      String encodedIv = jweHeader.getString("iv");
      iv = Base64.decodeUrl(encodedIv);
      header = jweHeader;
      headerStr = jweHeaderStr;
    } else {
      SecureRandom sr = new SecureRandom();
      iv = new byte[16]; // AES has one blocksize of 16 bytes = 128 bits
      sr.nextBytes(iv);
      header = new JSONObject(jweHeader.toString());
      header.put("iv", Base64.encodeBytes(iv, org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL));
      headerStr = header.toString();
    }
    IvParameterSpec parameters = new IvParameterSpec(iv);
    String encodedJweHeader = Base64.encodeBytes(headerStr.getBytes("utf-8"), org.xmldap.util.Base64.DONT_BREAK_LINES
        | org.xmldap.util.Base64.URL);

    String encodedJweCiphertext;
    String encodedJweIntegrityValue;
    int cekLength = enc2cekLength(jwtEncStr);
    byte[] cek = generateCEK(contentEncryptionKey.getEncoded(), cekLength);
    {
      System.out.println("base64 cek="
          + Base64.encodeBytes(cek, org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL));
      byte[] cipherTextBytes = CryptoUtils.jwtAesCbcEncrypt(contentBytes, cek, parameters);
      encodedJweCiphertext = Base64.encodeBytes(cipherTextBytes, org.xmldap.util.Base64.DONT_BREAK_LINES
          | org.xmldap.util.Base64.URL);
      {
        String stringToSign = encodedJweHeader + "." + encodedJweEncryptedKey + "." + encodedJweCiphertext;
        String jwtIntStr = jweHeader.getString("int");
        int cikLength = int2cikLength(jwtIntStr);
        byte[] cik = generateCIK(contentEncryptionKey.getEncoded(), cikLength);
        byte[] bytes = doMac(jwtIntStr, cik, stringToSign.getBytes());
        encodedJweIntegrityValue = Base64.encodeBytes(bytes, org.xmldap.util.Base64.DONT_BREAK_LINES
            | org.xmldap.util.Base64.URL);
      }
    }
    StringBuffer sb = new StringBuffer(encodedJweHeader);
    sb.append('.');
    sb.append(encodedJweEncryptedKey);
    sb.append('.');
    sb.append(encodedJweCiphertext);
    sb.append('.');
    sb.append(encodedJweIntegrityValue);

    return sb.toString();
  }

  private static String encryptAesGcm(byte[] contentBytes, String jweHeaderStr, SecretKey contentEncryptionKey,
      String encodedJweEncryptedKey) throws JSONException, UnsupportedEncodingException, Exception,
      InvalidCipherTextException {
    String encodedJweHeader = Base64.encodeBytes(jweHeaderStr.getBytes("utf-8"),
        org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);

    String b64;
    String encodedJweCiphertext;
    String encodedJweIntegrityValue;
    String headerStr = jweHeaderStr;
    byte[] ivBytes;
    JSONObject header = new JSONObject(jweHeaderStr);
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

    String associatedText = encodedJweHeader.concat(".").concat(encodedJweEncryptedKey);
    byte[] associatedTextBytes = associatedText.getBytes();

    System.out.println("contentEncryptionKey bitlength = " + (contentEncryptionKey.getEncoded().length * 8));
    // String[] result = CryptoUtils.aesgcmEncrypt(aeadParameters,
    // contentEncryptionKey, mJsonStr.getBytes("utf-8"));
    String[] result = CryptoUtils.aesgcmEncrypt(contentEncryptionKey.getEncoded(), contentBytes, ivBytes,
        associatedTextBytes);
    encodedJweCiphertext = result[0];
    encodedJweIntegrityValue = result[1];

    StringBuffer sb = new StringBuffer(encodedJweHeader);
    sb.append('.');
    sb.append(encodedJweEncryptedKey);
    sb.append('.');
    sb.append(encodedJweCiphertext);
    sb.append('.');
    sb.append(encodedJweIntegrityValue);

    return sb.toString();
  }

  static byte[] jwtDecrypt(String jwtStr, RSAPrivateKey aRsaPrivKey) throws Exception {

    String[] split = jwtStr.split("\\.");
    if (split.length != 4) {
      throw new Exception("jwt format exception #" + split.length);
    }

    String encodedJwtHeaderSegment = split[0];
    String encodedJwtKeySegment = split[1];
    String encodedJwtCryptoSegment = split[2];
    String encodedJwtIntegritySegment = split[3];
    byte[] jwtIntegritySegmentBytes = Base64.decodeUrl(encodedJwtIntegritySegment);
    String jwtHeaderStr = new String(Base64.decodeUrl(encodedJwtHeaderSegment));
    JSONObject header = new JSONObject(jwtHeaderStr);

    String newKeySegment = split[1];
    byte[] cipheredKeyBytes = Base64.decodeUrl(newKeySegment);
    String jwtEncStr = (String) header.get("enc");
    String symmetricAlgorithm = getSymmetricAlgorithm(jwtEncStr);

    byte[] secretKeyBytes = decryptKey(aRsaPrivKey, symmetricAlgorithm, header, cipheredKeyBytes);

    return doJwtDecrypt(encodedJwtHeaderSegment, encodedJwtKeySegment, encodedJwtCryptoSegment,
        jwtIntegritySegmentBytes, header, secretKeyBytes);
  }

  public static String getSymmetricAlgorithm(String jwtEncStr) throws NoSuchAlgorithmException {
    // int keylength;
    // if (ENC_ALG_A128CBC.equals(jwtEncStr)) {
    // keylength = 128;
    // } else if (ENC_ALG_A192CBC.equals(jwtEncStr)) {
    // keylength = 192;
    // } else if (ENC_ALG_A256CBC.equals(jwtEncStr)) {
    // keylength = 256;
    // } else if (ENC_ALG_A512CBC.equals(jwtEncStr)) {
    // keylength = 512;
    // } else if (ENC_ALG_A128GCM.equals(jwtEncStr)) {
    // keylength = 128;
    // } else if (ENC_ALG_A192GCM.equals(jwtEncStr)) {
    // keylength = 192;
    // } else if (ENC_ALG_A256GCM.equals(jwtEncStr)) {
    // keylength = 256;
    // } else if (ENC_ALG_A512GCM.equals(jwtEncStr)) {
    // keylength = 512;
    // } else {
    // throw new NoSuchAlgorithmException("JWT algorithm: " + jwtEncStr);
    // }
    return "AES";
  }

  // public static byte[] decrypt(String encrypted, RSAPrivateKey rsaPrivateKey)
  // throws Exception {
  // String[] split = encrypted.split("\\.");
  // String encodedJwtHeaderSegment = split[0];
  // String encodedJwtKeySegment = split[1];
  // String encodedJwtCryptoSegment = split[2];
  // String encodedJwtIntegritySegment = split[3];
  //
  // String jwtHeaderSegment = new
  // String(Base64.decodeUrl(encodedJwtHeaderSegment));
  //
  // byte[] jwtIntegritySegmentBytes =
  // Base64.decodeUrl(encodedJwtIntegritySegment);
  //
  // JSONObject header = new JSONObject(jwtHeaderSegment);
  // String jwtEncStr = (String) header.get("enc");
  // String symmetricAlgorithm = getSymmetricAlgorithm(jwtEncStr);
  //
  // byte[] cipheredKeyBytes = Base64.decodeUrl(encodedJwtKeySegment);
  //
  // byte[] secretKeyBytes = decryptKey(rsaPrivateKey, symmetricAlgorithm,
  // header, cipheredKeyBytes);
  // // SecretKeySpec keySpec = new SecretKeySpec(secretKeyBytes, "AES");
  //
  // return doDecrypt(encodedJwtHeaderSegment, encodedJwtKeySegment,
  // encodedJwtCryptoSegment, jwtIntegritySegmentBytes,
  // header, secretKeyBytes);
  //
  // // if ((ENC_ALG_A128CBC.equals(jwtEncStr)) ||
  // // (ENC_ALG_A192CBC.equals(jwtEncStr))
  // // || (ENC_ALG_A256CBC.equals(jwtEncStr)) ||
  // // (ENC_ALG_A512CBC.equals(jwtEncStr))) {
  // // int cekLength = enc2cekLength(jwtEncStr);
  // // byte[] cek = generateCEK(keySpec.getEncoded(), cekLength);
  // //
  // // System.out.println("base64 CEK="
  // // + Base64.encodeBytes(cek, org.xmldap.util.Base64.DONT_BREAK_LINES |
  // // org.xmldap.util.Base64.URL));
  // //
  // // byte[] jwtCryptoSegmentBytes =
  // Base64.decodeUrl(encodedJwtCryptoSegment);
  // // byte[] cleartext = CryptoUtils.decryptAESCBC(jwtCryptoSegmentBytes,
  // cek);
  // // String jwtIntStr = (String) header.get("int");
  // // int cikLength = int2cikLength(jwtIntStr);
  // // byte[] cik = generateCIK(keySpec.getEncoded(), cikLength);
  // // String stringToSign = encodedJwtHeaderSegment + "." +
  // // encodedJwtKeySegment + "." + encodedJwtCryptoSegment;
  // // byte[] bytes = doMac(jwtIntStr, cik, stringToSign.getBytes());
  // // if (Arrays.constantTimeAreEqual(bytes, jwtIntegritySegmentBytes)) {
  // // return cleartext;
  // // } else {
  // // throw new Exception("jwt integrity check failed");
  // // }
  // // }
  // // if ((ENC_ALG_A128GCM.equals(jwtEncStr)) ||
  // // (ENC_ALG_A192GCM.equals(jwtEncStr))
  // // || (ENC_ALG_A256GCM.equals(jwtEncStr)) ||
  // // (ENC_ALG_A512GCM.equals(jwtEncStr))) {
  // // String ivB64 = header.getString("iv");
  // // byte[] ivBytes = Base64.decodeUrl(ivB64);
  // // KeyParameter key = new KeyParameter(keySpec.getEncoded());
  // // int macSizeBits = 128;
  // //
  // // byte[] nonce = ivBytes;
  // // String associatedText = encodedJwtHeaderSegment + "." +
  // // encodedJwtKeySegment;
  // // AEADParameters aeadParameters = new AEADParameters(key, macSizeBits,
  // // nonce, associatedText.getBytes());
  // // byte[] jwtCryptoSegmentBytes =
  // Base64.decodeUrl(encodedJwtCryptoSegment);
  // // return CryptoUtils.aesgcmDecrypt(aeadParameters, keySpec,
  // // jwtCryptoSegmentBytes, jwtIntegritySegmentBytes);
  // // } else {
  // // throw new NoSuchAlgorithmException("RSA AES decrypt " + jwtEncStr);
  // // }
  // }

  private static byte[] decryptKey(RSAPrivateKey rsaPrivateKey, String symmetricAlgorithm, JSONObject header,
      byte[] cipheredKeyBytes) throws JSONException, NoSuchAlgorithmException, NoSuchPaddingException,
      InvalidKeyException, IllegalBlockSizeException, BadPaddingException, CryptoException {
    String jwtAlgStr = (String) header.get("alg");
    if (ENC_ALG_RSA1_5.equals(jwtAlgStr)) {
      Cipher encrypter = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      encrypter.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
      return encrypter.doFinal(cipheredKeyBytes);
    } else if (ENC_ALG_RSA_OAEP.equals(jwtAlgStr)) {
      return CryptoUtils.decryptRSAOAEP(cipheredKeyBytes, rsaPrivateKey);
    } else {
      throw new NoSuchAlgorithmException("RSA decrypt " + jwtAlgStr);
    }
  }
}
