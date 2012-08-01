package org.xmldap.json;

import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;

import junit.framework.TestCase;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jcajce.provider.asymmetric.ec.ECUtil;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.json.JSONObject;
import org.junit.Test;
import org.xmldap.util.Base64;

public class WebTokenCipherSpiTest  extends TestCase {
  JSONObject joeO = null;

  final String joeStr = "{\"iss\":\"joe\",\r\n" + " \"exp\":1300819380,\r\n" + " \"http://example.com/is_root\":true}";

  final String hs256 = "{\"typ\":\"JWT\",\r\n" + " \"alg\":\"HS256\"}";
  final String hs384 = "{\"typ\":\"JWT\",\r\n" + " \"alg\":\"HS384\"}";
  final String hs512 = "{\"typ\":\"JWT\",\r\n" + " \"alg\":\"HS512\"}";
  final byte[] hsKey = { 3, (byte) 35, (byte) 53, (byte) 75, (byte) 43, (byte) 15, (byte) 165, (byte) 188, (byte) 131,
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

  String a128kw = "{\"alg\":\"A128KW\", \"enc\":\"A128GCM\", \"iv\":\"AxY8DCtDaGlsbGljb3RoZQ\"}";
  String a256kw = "{\"alg\":\"A256KW\", \"int\":\"HS256\", \"enc\":\"A256CBC\", \"iv\":\"AxY8DCtDaGlsbGljb3RoZQ\"}";

  String A128GCM = "{\"alg\":\"A128GCM\"}";

  String re256GCM = "{\"alg\":\"RSA1_5\",\r\n" + "\"enc\":\"A256GCM\",\r\n" + "\"iv\":\"AxY8DCtDaGlsbGljb3RoZQ\",\r\n"
      + "\"x5t\":\"7noOPq-hJ1_hCnvWh6IeYI2w9Q0\"}";

  String re128GCM = "{\"alg\":\"RSA1_5\",\r\n" + "\"enc\":\"A128GCM\",\r\n" + "\"iv\":\"AxY8DCtDaGlsbGljb3RoZQ\",\r\n"
      + "\"x5t\":\"7noOPq-hJ1_hCnvWh6IeYI2w9Q0\"}";

  String a128kwb64;
  String a256kwb64;

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

  private JsonCryptoProvider provider;

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

      a128kwb64 = Base64.encodeBytes(a128kw.getBytes("utf-8"), org.xmldap.util.Base64.DONT_BREAK_LINES
          | org.xmldap.util.Base64.URL);
      a256kwb64 = Base64.encodeBytes(a256kw.getBytes("utf-8"), org.xmldap.util.Base64.DONT_BREAK_LINES
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

    provider = new JsonCryptoProvider();
    
  }

  public void testJsonCryptoProvider() throws Exception {
    WebTokenCipherSpi spi = new WebTokenCipherSpi();
    AlgorithmParameterSpec genParamSpec = new JsonCryptoParameterSpec(rsaOaepAesCbc128HeaderStr);
    AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("RSA15", provider);
    algorithmParameters.init(genParamSpec);
//    AlgorithmParameterGenerator apg = c.getInstance("RSA15", provider);
//    apg.init(genParamSpec);
//    AlgorithmParameters algorithmParameters = apg.generateParameters();
    spi.engineInit(Cipher.ENCRYPT_MODE, rsaPublicKey, algorithmParameters, new SecureRandom());
    byte[] ciphertext = spi.engineDoFinal(joeStr.getBytes(), 0, joeStr.getBytes().length);
  }

  @Test
  void testRsa(String name, String jwtHeaderSegment, String jwtHeaderSegmentB64) throws Exception {
    System.out.println("jwtHeaderSegment: " + name + " " + jwtHeaderSegment);
    System.out.println("jwtHeaderSegment: " + name + " " + jwtHeaderSegmentB64);

    AlgorithmParameterGenerator apg = AlgorithmParameterGenerator.getInstance("RSA15", provider);
    apg.init(new JsonCryptoParameterSpec(jwtHeaderSegment));
    AlgorithmParameters params = apg.generateParameters();
    AlgorithmParameters p = AlgorithmParameters.getInstance("RSA15", provider);
    p.init(new JsonCryptoParameterSpec(jwtHeaderSegment));
    
    WebTokenCipherSpi spi = new WebTokenCipherSpi();
    spi.engineInit(Cipher.ENCRYPT_MODE, rsaPublicKey, params , new SecureRandom());
    byte[] encryptedBytes = spi.engineDoFinal(joeStr.getBytes(), 0, joeStr.getBytes().length);
    String encrypted = new String(encryptedBytes);
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

    byte[] cleartextBytes = WebToken.jwtDecrypt(encrypted, rsaPrivKey);
    assertEquals(joeStr, new String(cleartextBytes));
  }

}
