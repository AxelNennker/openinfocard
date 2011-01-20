package org.xmldap.json;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.json.JSONException;
import org.json.JSONObject;
import org.xmldap.util.Base64;

public class WebToken {
  String mJsonStr = null;
  PrivateKey mPrivateKey = null;
  String mPKAlgorithm = null; 
  
  public WebToken(String jso, String algorithm) {
    mJsonStr = jso;
    mPKAlgorithm = algorithm;
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
    
    DERObjectIdentifier oid;
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
    ECDomainParameters ecDomainParameters = new ECDomainParameters(
        curve, 
        x9ECParameters.getG(), 
        x9ECParameters.getN(), 
        x9ECParameters.getH(),
        x9ECParameters.getSeed());
    ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(
        q, ecDomainParameters);
    verifier.init(false, ecPublicKeyParameters);
    String hp = jwtHeaderSegment + "." + jwtPayloadSegment;
    byte[] bytes = hp.getBytes("utf-8");
    digest.update(bytes, 0, bytes.length);
    byte[] out = new byte[digest.getDigestSize()];
    int result = digest.doFinal(out, 0);
    
    boolean verified = verifier.verifySignature(out, r, s);
    return verified;
  }
  
  
   public String serialize(BigInteger D) 
    throws NoSuchAlgorithmException, JSONException, InvalidKeyException, SignatureException, IOException, InvalidKeySpecException {
    
    DERObjectIdentifier oid;
    Digest digest;
    JSONObject header = new JSONObject(mPKAlgorithm);
    String jwtAlgStr = (String) header.get("alg");
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
    ECDomainParameters ecParameterSpec = new ECDomainParameters(
        x9ECParameters.getCurve(), 
        x9ECParameters.getG(), 
        x9ECParameters.getN(), 
        x9ECParameters.getH(), 
        x9ECParameters.getSeed());
    ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(
        D, ecParameterSpec);

    
    String b64 = Base64.encodeBytes(mPKAlgorithm.getBytes("utf-8"), 
        org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
    StringBuffer sb = new StringBuffer(b64);
    sb.append('.');
    b64 = Base64.encodeBytes(mJsonStr.getBytes("utf-8"), 
        org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
    sb.append(b64);
    
    String stringToSign = sb.toString();
    byte[] bytes = stringToSign.getBytes("utf-8");
    digest.update(bytes, 0, bytes.length);
    byte[] out = new byte[digest.getDigestSize()];
    int result = digest.doFinal(out, 0);

    sb.append('.');
    
    String signed = signECDSA(ecPrivateKeyParameters, out);

    sb.append(signed);
    return sb.toString();
  }

  private String signECDSA(ECPrivateKeyParameters ecPrivateKeyParameters, byte[] bytes) throws UnsupportedEncodingException {
    ECDSASigner signer = new ECDSASigner();
    signer.init(true, ecPrivateKeyParameters);
    BigInteger[] res = signer.generateSignature(bytes);
    BigInteger r = res[0];
    BigInteger s = res[1];
    
    String signed = rs2jwt(r, s);
    //System.out.println("Signed:" + signed);
    return signed;
  }

  private String rs2jwt(BigInteger r, BigInteger s) {
    //    System.out.println("R:" + r.toString());
    //    System.out.println("S:" + s.toString());
        byte[] rBytes = r.toByteArray();
    //    System.out.println("rBytes.length:" + rBytes.length);
        byte[] sBytes = s.toByteArray();
    //    System.out.println("sBytes.length:" + sBytes.length);
    //    StringBuffer sb = new StringBuffer();
    //    for (int i=0; i<rBytes.length;i++) {
    //      sb.append(String.valueOf((int)rBytes[i]));
    //      sb.append(',');
    //    }
    //    System.out.println("Rbytes:" + sb.toString());
    //    sb = new StringBuffer();
    //    for (int i=0; i<sBytes.length;i++) {
    //      sb.append(String.valueOf((int)sBytes[i]));
    //      sb.append(',');
    //    }
    //    System.out.println("Sbytes:" + sb.toString());
        byte[] rsBytes = new byte[64];
        for (int i=0; i<rsBytes.length; i++) {
          rsBytes[i] = 0;
        }
        if (rBytes.length >= 32) {
          System.arraycopy(rBytes, rBytes.length - 32, rsBytes, 0, 32);
        } else {
          System.arraycopy(rBytes, 0, rsBytes, 32-rBytes.length, rBytes.length);
        }
        if (sBytes.length >= 32) {
          System.arraycopy(sBytes, sBytes.length - 32, rsBytes, 32, 32);
        } else {
          System.arraycopy(sBytes, 0, rsBytes, 64-sBytes.length, sBytes.length);
        }
        String signed = Base64.encodeBytes(rsBytes, 
            org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
    return signed;
  }

  public String serialize(RSAPrivateKey privateKey) throws JSONException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
    String b64 = Base64.encodeBytes(mPKAlgorithm.getBytes("utf-8"), 
        org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
    StringBuffer sb = new StringBuffer(b64);
    sb.append('.');
    b64 = Base64.encodeBytes(mJsonStr.getBytes("utf-8"), 
        org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
    sb.append(b64);
    
    String stringToSign = sb.toString();
    
    sb.append('.');
    
    JSONObject algO = new JSONObject(mPKAlgorithm);
    String jwtAlgStr = algO.getString("alg");
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

    b64 = Base64.encodeBytes(bytes, 
        org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
    sb.append(b64);
    return sb.toString();
  }

//  public String serialize(PrivateKey privateKey) 
//    throws UnsupportedEncodingException, JSONException, 
//    NoSuchAlgorithmException, InvalidKeyException, SignatureException 
//  {
//    String b64 = Base64.encodeBytes(mPKAlgorithm.getBytes("utf-8"), 
//        org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
//    StringBuffer sb = new StringBuffer(b64);
//    sb.append('.');
//    b64 = Base64.encodeBytes(mJsonStr.getBytes("utf-8"), 
//        org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
//    sb.append(b64);
//    sb.append('.');
//    
//    JSONObject algO = new JSONObject(mPKAlgorithm);
//    String jwtAlgStr = algO.getString("alg");
//
//    Signature signature = Signature.getInstance(jwtAlgStr);
//    signature.initSign(privateKey);
//    signature.update(mJsonStr.getBytes("utf-8"));
//    byte[] bytes = signature.sign();
//    String signed = new String(bytes);
//    sb.append(signed);
//    return sb.toString();
//  }

public String serialize(byte[] passphraseBytes) 
    throws JSONException, NoSuchAlgorithmException, InvalidKeyException, IllegalStateException, UnsupportedEncodingException {
    String     b64 = Base64.encodeBytes(mPKAlgorithm.getBytes("utf-8"), 
        org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
    StringBuffer sb = new StringBuffer(b64);
    sb.append('.');
    b64 = Base64.encodeBytes(mJsonStr.getBytes("utf-8"), 
        org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
    sb.append(b64);
    
    String stringToSign = sb.toString();
    
    sb.append('.');
    String signed;
    
    JSONObject algO = new JSONObject(mPKAlgorithm);
    String jwtAlgStr = algO.getString("alg");
    String algorithm;
    if ("HS256".equals(jwtAlgStr)) { // HMAC SHA-256
      algorithm = "HMACSHA256";
    } else if ("HS384".equals(jwtAlgStr)) { // HMAC SHA-384
      algorithm = "HMACSHA384";
    } else if ("HS512".equals(jwtAlgStr)) { // HMAC SHA-512
      algorithm = "HMACSHA512";
    } else {
      throw new NoSuchAlgorithmException("JWT shared secret" + jwtAlgStr);
    }
    Mac mac = Mac.getInstance(algorithm);
    mac.init(new SecretKeySpec(passphraseBytes, mac.getAlgorithm()));
    mac.update(stringToSign.getBytes("utf-8"));
    byte[] bytes = mac.doFinal();
    signed = Base64.encodeBytes(bytes, 
        org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
    sb.append(signed);
    return sb.toString();
  }
}
