/*
 * Copyright (c) 2006, Chuck Mortimore - xmldap.org
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
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESLightEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.xmldap.exceptions.CryptoException;
import org.xmldap.exceptions.SerializationException;
import org.xmldap.util.Base64;

/**
 * CryptUtils provides a number of general purpose crypto utilities. Digests,
 * encrypt, decrupt, etc
 * 
 * @author charliemortimore at gmail.com
 */
/**
 * @author ignisvulpis
 *
 */
/**
 * @author ignisvulpis
 *
 */
public class CryptoUtils {

  public static String convertSigningAlgorithm(String signatureAlgorithm) throws SerializationException {
    if (signatureAlgorithm.equalsIgnoreCase("SHA1withRSA")) {
      return "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    }
    if (signatureAlgorithm.equalsIgnoreCase("SHA256withRSA")) {
      return "http://www.w3.org/2000/09/xmldsig#rsa-sha256";
    }
    throw new SerializationException("unsupported signature algorithm");
  }

  public static String convertMessageDigestAlgorithm(String signatureAlgorithm) throws SerializationException {
    if (signatureAlgorithm.equalsIgnoreCase("SHA")) {
      return "http://www.w3.org/2000/09/xmldsig#sha1";
    }
    if (signatureAlgorithm.equalsIgnoreCase("SHA1")) {
      return "http://www.w3.org/2000/09/xmldsig#sha1";
    }
    if (signatureAlgorithm.equalsIgnoreCase("SHA-1")) {
      return "http://www.w3.org/2000/09/xmldsig#sha1";
    }
    if (signatureAlgorithm.equalsIgnoreCase("SHA256")) {
      return "http://www.w3.org/2000/09/xmldsig#sha256";
    }
    if (signatureAlgorithm.equalsIgnoreCase("SHA-256")) {
      return "http://www.w3.org/2000/09/xmldsig#sha256";
    }
    throw new SerializationException("unsupported signature algorithm");
  }

  public static String convertMessageDigestAlgorithmUrl(String signatureAlgorithmUrl) throws CryptoException {
    if (signatureAlgorithmUrl.equals("http://www.w3.org/2000/09/xmldsig#sha1")) {
      return "SHA";
    }
    if (signatureAlgorithmUrl.equals("http://www.w3.org/2001/04/xmlenc#sha256")) {
      return "SHA256";
    }
    if (signatureAlgorithmUrl.equals("http://www.w3.org/2000/09/xmldsig#sha256")) {
      return "SHA256";
    }
    throw new CryptoException("unsupported signature algorithm");
  }

  public static byte[] byteDigest(byte[] data, String messageDigestAlgorithm) throws CryptoException {

    MessageDigest md;
    try {
      md = MessageDigest.getInstance(messageDigestAlgorithm);
    } catch (NoSuchAlgorithmException e) {
      throw new CryptoException(e);
    }
    md.reset();
    md.update(data);
    return md.digest();

  }

  /**
   * Creates a Base64 encoded Digest of a byte[]
   * 
   * @param data
   *          the data to digest
   * @return Base64 encoded digest of the data
   * @throws CryptoException
   */
  public static String digest(byte[] data, String messageDigestAlgorithm) throws CryptoException {
    return Base64.encodeBytesNoBreaks(byteDigest(data, messageDigestAlgorithm));
  }

  /**
   * @param keys
   * @param iv
   * @param dataBytes
   * @return
   * @throws CryptoException
   */
  public static byte[] aesCbcEncrypt(byte[] encryptionKey, byte[] iv, ByteArrayOutputStream dataBytes)
      throws CryptoException {
    // encrypt
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    try {
      AESLightEngine aes = new AESLightEngine();
      CBCBlockCipher cbc = new CBCBlockCipher(aes);
      BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cbc);
      KeyParameter key = new KeyParameter(encryptionKey);
      ParametersWithIV paramWithIV = new ParametersWithIV(key, iv);
      byte inputBuffer[] = new byte[16];
      byte outputBuffer[] = new byte[16];
      int bytesProcessed = 0;
      cipher.init(true, paramWithIV);
      int bytesRead = 0;
      ByteArrayInputStream inputStream = new ByteArrayInputStream(dataBytes.toByteArray());
      while ((bytesRead = inputStream.read(inputBuffer)) > 0) {
        bytesProcessed = cipher.processBytes(inputBuffer, 0, bytesRead, outputBuffer, 0);
        if (bytesProcessed > 0)
          outputStream.write(outputBuffer, 0, bytesProcessed);
      }
      bytesProcessed = cipher.doFinal(outputBuffer, 0);
      if (bytesProcessed > 0)
        outputStream.write(outputBuffer, 0, bytesProcessed);
    } catch (Exception e) {
      throw new CryptoException("Error encrypting data", e);
    }

    byte[] cipherText = outputStream.toByteArray();
    return cipherText;
  }

  /**
   * Encrypts data using AES with a Chained Block Cipber. Base64 encode the
   * result
   * 
   * @param text
   *          The data to encrypt
   * @param keybytes
   *          the key
   * @return the cipherText in a Stringbuffer
   * @throws CryptoException
   */
  public static String encryptAESCBC(String data, byte[] keybytes) throws CryptoException {
    return Base64.encodeBytesNoBreaks(aesCbcEncrypt(data, keybytes));
  }

  public static String encryptAESCBCB64URL(String data, byte[] keybytes) throws CryptoException {
    return Base64.encodeBytes(aesCbcEncrypt(data, keybytes), org.xmldap.util.Base64.DONT_BREAK_LINES
        | org.xmldap.util.Base64.URL);
  }

  public static byte[] aesCbcEncrypt(String data, byte[] keybytes) throws CryptoException {
    SecureRandom sr = new SecureRandom();
    return aesCbcEncrypt(data, keybytes, sr);
  }

  public static byte[] jwtAesCbcEncrypt(byte[] contentBytes, byte[] keybytes, IvParameterSpec parameters) throws CryptoException {
    Cipher cipher;
    try {
      cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      SecretKeySpec keyspec = new SecretKeySpec(keybytes, "AES");
      cipher.init(Cipher.ENCRYPT_MODE, keyspec, parameters);
      return cipher.doFinal(contentBytes);
    } catch (NoSuchAlgorithmException e) {
      throw new CryptoException(e);
    } catch (NoSuchPaddingException e) {
      throw new CryptoException(e);
    } catch (InvalidKeyException e) {
      throw new CryptoException(e);
    } catch (InvalidAlgorithmParameterException e) {
      throw new CryptoException(e);
    } catch (IllegalBlockSizeException e) {
      throw new CryptoException(e);
    } catch (BadPaddingException e) {
      throw new CryptoException(e);
    }
  }

  /*
   * Result byte array ivBytes || ciphertextBytes
   */
  public static byte[] aesCbcEncrypt(String data, byte[] keybytes, SecureRandom sr) throws CryptoException {

    Cipher cipher;
    try {
      cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      int blocksize = cipher.getBlockSize();
      byte[] ivBytes = new byte[blocksize];
      sr.nextBytes(ivBytes);
      IvParameterSpec parameters = new IvParameterSpec(ivBytes);
      SecretKeySpec keyspec = new SecretKeySpec(keybytes, "AES");
      cipher.init(Cipher.ENCRYPT_MODE, keyspec, parameters);
      byte[] ciphertextBytes = cipher.doFinal(data.getBytes());

      byte[] resultBytes = new byte[ivBytes.length + ciphertextBytes.length];
      System.arraycopy(ivBytes, 0, resultBytes, 0, ivBytes.length);
      System.arraycopy(ciphertextBytes, 0, resultBytes, ivBytes.length, ciphertextBytes.length);
      return resultBytes;

    } catch (NoSuchAlgorithmException e) {
      throw new CryptoException(e);
    } catch (NoSuchPaddingException e) {
      throw new CryptoException(e);
    } catch (InvalidKeyException e) {
      throw new CryptoException(e);
    } catch (InvalidAlgorithmParameterException e) {
      throw new CryptoException(e);
    } catch (IllegalBlockSizeException e) {
      throw new CryptoException(e);
    } catch (BadPaddingException e) {
      throw new CryptoException(e);
    }
  }

  /**
   * Decryptes AES with a Chained Block Cipher
   * 
   * @param text
   *          The cipher text
   * @param keybytes
   *          the decryptiong key
   * @return clearText in a StringBuffer
   * @throws CryptoException
   */
  public static byte[] decryptAESCBC(String b64encodedCipherText, byte[] keybytes) throws CryptoException {
    byte[] ciphertext = Base64.decode(b64encodedCipherText);
    return decryptAESCBC(ciphertext, keybytes);
  }

  public static byte[] decryptAESCBC(byte[] ciphertext, byte[] keybytes) throws CryptoException {
    try {
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      int blocksize = cipher.getBlockSize();
      byte[] ivBytes = new byte[blocksize];
      System.arraycopy(ciphertext, 0, ivBytes, 0, blocksize);
      IvParameterSpec ivParameter = new IvParameterSpec(ivBytes);
      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keybytes, "AES"), ivParameter);
      return cipher.doFinal(ciphertext, blocksize, ciphertext.length - blocksize);
    } catch (NoSuchAlgorithmException e) {
      throw new CryptoException(e);
    } catch (NoSuchPaddingException e) {
      throw new CryptoException(e);
    } catch (InvalidKeyException e) {
      throw new CryptoException(e);
    } catch (InvalidAlgorithmParameterException e) {
      throw new CryptoException(e);
    } catch (IllegalBlockSizeException e) {
      throw new CryptoException(e);
    } catch (BadPaddingException e) {
      throw new CryptoException(e);
    }
  }

  public static byte[] jwtAesCbcDecrypt(byte[] ciphertext, byte[] keybytes, IvParameterSpec ivParameter) throws CryptoException {
    try {
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keybytes, "AES"), ivParameter);
      return cipher.doFinal(ciphertext);
    } catch (NoSuchAlgorithmException e) {
      throw new CryptoException(e);
    } catch (NoSuchPaddingException e) {
      throw new CryptoException(e);
    } catch (InvalidKeyException e) {
      throw new CryptoException(e);
    } catch (InvalidAlgorithmParameterException e) {
      throw new CryptoException(e);
    } catch (IllegalBlockSizeException e) {
      throw new CryptoException(e);
    } catch (BadPaddingException e) {
      throw new CryptoException(e);
    }
  }

  /**
   * Encrypts using RSA with OAEP
   * 
   * @param input
   *          the clear text to encrypt
   * @param cert
   *          the certificate to use for encryption
   * @return the base64 encoded cipher text
   * @throws CryptoException
   */
  public static byte[] rsaoaepEncryptBytes(byte[] input, RSAPublicKey rsaPublicKey) throws CryptoException {

    AsymmetricBlockCipher engine = new RSAEngine();
    OAEPEncoding cipher = new OAEPEncoding(engine);

    // PublicKey pk = cert.getPublicKey();
    // String algorithm = pk.getAlgorithm();
    // if (!algorithm.equalsIgnoreCase("RSA")) {
    // throw new CryptoException("Algorithm " + algorithm +
    // " is not supported");
    // }
    //
    // //populate modulus
    // RSAPublicKey rsaPublicKey = (RSAPublicKey) pk;
    BigInteger mod = rsaPublicKey.getModulus();
    BigInteger exp = rsaPublicKey.getPublicExponent();
    RSAKeyParameters keyParams = new RSAKeyParameters(false, mod, exp);
    cipher.init(true, keyParams);

    // int inputBlockSize = cipher.getInputBlockSize();
    // int outputBlockSize = cipher.getOutputBlockSize();

    byte[] cipherText;
    try {
      cipherText = cipher.processBlock(input, 0, input.length);
    } catch (InvalidCipherTextException e) {

      throw new CryptoException(e);
    }

    return cipherText;

  }

  public static String rsaoaepEncrypt(byte[] input, RSAPublicKey rsaPublicKey) throws CryptoException {
    byte[] cipherText = rsaoaepEncryptBytes(input, rsaPublicKey);
    return Base64.encodeBytesNoBreaks(cipherText);
  }

  /**
   * Decrypts base 64 encoded data using RSA OAEP and the provided Key
   * 
   * @param b64EncodedData
   *          the base 64 encoded ciphertext
   * @param inputKey
   *          the private key to use for decryption
   * @return a byte[] of clear text
   * @throws CryptoException
   */
  public static byte[] decryptRSAOAEP(byte[] cipherText, PrivateKey inputKey) throws CryptoException {

    RSAPrivateKey key = (RSAPrivateKey) inputKey;
    RSAEngine engine = new RSAEngine();
    OAEPEncoding cipher = new OAEPEncoding(engine);
    BigInteger mod = key.getModulus();
    BigInteger exp = key.getPrivateExponent();
    RSAKeyParameters keyParams = new RSAKeyParameters(true, mod, exp);
    cipher.init(false, keyParams);

    byte[] clearText;

    try {
      clearText = cipher.processBlock(cipherText, 0, cipherText.length);
    } catch (InvalidCipherTextException e) {

      throw new CryptoException(e);
    }

    return clearText;

  }

  public static byte[] decryptRSAOAEP(String b64EncodedData, PrivateKey inputKey) throws CryptoException {
    byte[] cipherText = Base64.decode(b64EncodedData);
    return decryptRSAOAEP(cipherText, inputKey);
  }

  /**
   * Generates an AES SecretKey of a specified bit length
   * 
   * @param bitSize
   *          length of key
   * @return the encoded key as a byte[]
   * @throws CryptoException
   */
  public static byte[] genKey(int bitSize) throws CryptoException {

    KeyGenerator keygen;
    try {
      keygen = KeyGenerator.getInstance("AES");
    } catch (NoSuchAlgorithmException e) {

      throw new CryptoException(e);
    }

    keygen.init(bitSize);
    SecretKey key = keygen.generateKey();
    return key.getEncoded();

  }

  /**
   * Generates an AES SecretKey of a specified bit length
   * 
   * @param bitSize
   *          length of key
   * @return the key as a byte[]
   * @throws CryptoException
   */
  public static SecretKey genAesKey(int bitSize) throws CryptoException {

    KeyGenerator keygen;
    try {
      keygen = KeyGenerator.getInstance("AES");
    } catch (NoSuchAlgorithmException e) {

      throw new CryptoException(e);
    }

    keygen.init(bitSize);
    return keygen.generateKey();

  }

  /**
   * Verifies a public signature
   * 
   * @param data
   *          the signed data
   * @param signature
   *          the signature
   * @param mod
   *          modulus
   * @param exp
   *          exponent
   * @return valid or invalid
   * @throws CryptoException
   */
  public static boolean verifyRSA(byte[] data, byte[] signature, BigInteger mod, BigInteger exp,
      String messageDigestAlgorithm // SHA or SHA256
  ) throws CryptoException {

    boolean verified = false;

    try {

      RSAPublicKeySpec rsaKeySpec = new RSAPublicKeySpec(mod, exp);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      PublicKey pubKey = keyFactory.generatePublic(rsaKeySpec);
      String signatureAlgorithm = null;
      if ("SHA".equals(messageDigestAlgorithm)) {
        signatureAlgorithm = "SHA1withRSA";
      } else if ("SHA256".equals(messageDigestAlgorithm)) {
        signatureAlgorithm = "SHA256withRSA";
      }
      if (signatureAlgorithm == null) {
        throw new CryptoException("Unsupported digest algorithm " + messageDigestAlgorithm);
      }
      Signature sig = Signature.getInstance(signatureAlgorithm);
      sig.initVerify(pubKey);
      sig.update(data);
      verified = sig.verify(signature);
      // System.out.println("verify(): " + verified);

    } catch (NoSuchAlgorithmException e) {
      throw new CryptoException(e);
    } catch (SignatureException e) {
      throw new CryptoException(e);
    } catch (InvalidKeyException e) {
      throw new CryptoException(e);
    } catch (InvalidKeySpecException e) {
      throw new CryptoException(e);
    }

    return verified;

  }

  /**
   * Signs data
   * 
   * @param data
   *          the data to sign
   * @param key
   *          the private key to use for signing
   * @return sgined data
   * @throws CryptoException
   */
  public static String sign(byte[] data, PrivateKey key, String algorithm) throws CryptoException {

    String signedData;

    try {

      Signature signature = Signature.getInstance(algorithm);
      signature.initSign(key);
      signature.update(data);
      signedData = Base64.encodeBytesNoBreaks(signature.sign());

    } catch (NoSuchAlgorithmException e) {

      throw new CryptoException(e);
    } catch (SignatureException e) {

      throw new CryptoException(e);
    } catch (InvalidKeyException e) {

      throw new CryptoException(e);
    }

    return signedData;

  }

  public static X509Certificate X509fromB64(String b64EncodedX509Certificate) throws CryptoException {
    StringBuffer sb = new StringBuffer("-----BEGIN CERTIFICATE-----\n");
    sb.append(b64EncodedX509Certificate);
    sb.append("\n-----END CERTIFICATE-----\n");

    ByteArrayInputStream bis = new ByteArrayInputStream(sb.toString().getBytes());
    CertificateFactory cf;
    try {
      cf = CertificateFactory.getInstance("X509");
    } catch (CertificateException e) {
      throw new CryptoException("Error creating X509 CertificateFactory", e);
    }
    try {
      X509Certificate certificate = (X509Certificate) cf.generateCertificate(bis);
      return certificate;
    } catch (CertificateException e) {
      // in case that the base64 coding is not compliant
      byte[] decodedBase64 = Base64.decode(b64EncodedX509Certificate);
      String b64 = Base64.encodeBytes(decodedBase64);
      X509Certificate certificate;
      try {
        sb = new StringBuffer("-----BEGIN CERTIFICATE-----\n");
        sb.append(b64);
        sb.append("\n-----END CERTIFICATE-----\n");

        bis = new ByteArrayInputStream(sb.toString().getBytes());
        certificate = (X509Certificate) cf.generateCertificate(bis);
      } catch (CertificateException e1) {
        throw new CryptoException("Error creating X509Certificate from base64-encoded String", e1);
      }
      return certificate;
    }

  }

  // https://developer-content.emc.com/docs/rsashare/share_for_java/1.1/dev_guide/group__JCESAMPLES__ENCDEC__SYMCIPHER__AESGCM.html
  public static byte[] aesgcmEncrypt(IvParameterSpec paramSpec, SecretKey secretKey, byte[] plaintext)
      throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,
      ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    Cipher aesEncrypter = Cipher.getInstance("AES/GCM/NoPadding", new BouncyCastleProvider());
    aesEncrypter.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
    byte[] ciphertext = aesEncrypter.doFinal(plaintext);

    return ciphertext;
  }

//  public static byte[] aesgcmDecrypt(IvParameterSpec ivParamSpec, SecretKey secretKey, byte[] ciphertext)
//      throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,
//      ShortBufferException, IllegalBlockSizeException, BadPaddingException {
//    Cipher aesEncrypter = Cipher.getInstance("AES/GCM/NoPadding", new BouncyCastleProvider());
//    aesEncrypter.init(Cipher.DECRYPT_MODE, secretKey, ivParamSpec);
//    byte[] plaintext = aesEncrypter.doFinal(ciphertext);
//
//    return plaintext;
//  }
//
  public static String[] aesgcmEncrypt(byte[] cmk, byte[] plaintextBytes, byte[] nonce,
      byte[] associatedTextBytes) throws IllegalStateException, InvalidCipherTextException {
    final int macSizeBits = 128; // FIXME why 128?
    SecretKey secretKey = new SecretKeySpec(cmk, "AES");
    KeyParameter key = new KeyParameter(cmk);
    AEADParameters aeadParameters = new AEADParameters(key, macSizeBits, nonce, associatedTextBytes);
    return aesgcmEncrypt(aeadParameters, secretKey, plaintextBytes);
  }

  public static String[] aesgcmEncrypt(AEADParameters aeadParameters, SecretKey secretKey, byte[] plaintextBytes)
      throws IllegalStateException, InvalidCipherTextException {
    final int macSize = aeadParameters.getMacSize() / 8;
    BlockCipher blockCipher = new AESEngine();
    CipherParameters params = new KeyParameter(secretKey.getEncoded());
    try {
      blockCipher.init(true, params);
    } catch (IllegalArgumentException e) {
      System.out.println("aesgcmEncrypt aead key length in bits = " + (aeadParameters.getKey().getKey().length * 8)); // FIXME
      System.out.println("aesgcmEncrypt key length in bits = " + (secretKey.getEncoded().length * 8)); // FIXME
      System.out.flush();
      throw e;
    }
    GCMBlockCipher aGCMBlockCipher = new GCMBlockCipher(blockCipher);
    aGCMBlockCipher.init(true, aeadParameters);
    int len = aGCMBlockCipher.getOutputSize(plaintextBytes.length);
    byte[] out = new byte[len];
    int outOff = aGCMBlockCipher.processBytes(plaintextBytes, 0, plaintextBytes.length, out, 0);
    outOff += aGCMBlockCipher.doFinal(out, outOff);
    byte[] cipherText = new byte[outOff - macSize];
    System.arraycopy(out, 0, cipherText, 0, cipherText.length);
    String cipherTextB64 = Base64.encodeBytes(cipherText, org.xmldap.util.Base64.DONT_BREAK_LINES
        | org.xmldap.util.Base64.URL);
    byte[] auth = new byte[macSize];
    System.arraycopy(out, outOff - macSize, auth, 0, auth.length);
    String authB64 = Base64.encodeBytes(auth, org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
    return new String[] { cipherTextB64, authB64 };
  }

  public static byte[] aesgcmDecrypt(AEADParameters aeadParameters, SecretKey secretKey, byte[] ciphertext, byte[] auth)
      throws IllegalStateException, InvalidCipherTextException {
    BlockCipher blockCipher = new AESEngine();
    CipherParameters params = new KeyParameter(secretKey.getEncoded());
    blockCipher.init(false, params);
    GCMBlockCipher aGCMBlockCipher = new GCMBlockCipher(blockCipher);
    aGCMBlockCipher.init(false, aeadParameters);
    byte[] input = new byte[ciphertext.length + auth.length];
    System.arraycopy(ciphertext, 0, input, 0, ciphertext.length);
    System.arraycopy(auth, 0, input, ciphertext.length, auth.length);
    int len = aGCMBlockCipher.getOutputSize(input.length);
    byte[] out = new byte[len];
    int outOff = aGCMBlockCipher.processBytes(input, 0, input.length, out, 0);
    outOff += aGCMBlockCipher.doFinal(out, outOff);

    return out;
  }

  public static byte[] wrapAesKey(SecretKey keyToBeWrapped, SecretKey keyEncryptionKey)
      throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
      BadPaddingException {
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.WRAP_MODE, keyEncryptionKey);
    return cipher.wrap(keyToBeWrapped);
  }

  public static Key unwrapAesKey(byte[] keyToBeUnwrapped, SecretKey keyEncryptionKey) throws NoSuchAlgorithmException,
      NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.UNWRAP_MODE, keyEncryptionKey);
    return cipher.unwrap(keyToBeUnwrapped, "AES", Cipher.SECRET_KEY);
  }

}
