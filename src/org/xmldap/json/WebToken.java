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
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
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
  
  public String serialize(ECPrivateKeyParameters ecPrivateKeyParameters) 
    throws NoSuchAlgorithmException, JSONException, InvalidKeyException, SignatureException, IOException, InvalidKeySpecException {
    String b64 = Base64.encodeBytes(mPKAlgorithm.getBytes("utf-8"), 
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

    if ("ES256".equals(jwtAlgStr)) {
      signed = signES256a(ecPrivateKeyParameters, stringToSign.getBytes("utf-8"));
    } else {
      throw new NoSuchAlgorithmException("JWT privatekey " + jwtAlgStr);
    }
    sb.append(signed);
    return sb.toString();
  }

  private String signES256a(ECPrivateKeyParameters ecPrivateKeyParameters, byte[] bytes) throws UnsupportedEncodingException {
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
    if ("RS256".equals(jwtAlgStr)) {
      String algorithm = "SHA256withRSA";
      
      signature = Signature.getInstance(algorithm);
    } else {
      throw new NoSuchAlgorithmException("JWT algorithm: " + jwtAlgStr);
    }
    signature.initSign(privateKey);
    signature.update(stringToSign.getBytes("utf-8"));
    byte[] bytes = signature.sign();

    b64 = Base64.encodeBytes(bytes, 
        org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
    sb.append(b64);
    return sb.toString();
  }

  public String serialize(PrivateKey privateKey) 
    throws UnsupportedEncodingException, JSONException, 
    NoSuchAlgorithmException, InvalidKeyException, SignatureException 
  {
    String b64 = Base64.encodeBytes(mPKAlgorithm.getBytes("utf-8"), 
        org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
    StringBuffer sb = new StringBuffer(b64);
    sb.append('.');
    b64 = Base64.encodeBytes(mJsonStr.getBytes("utf-8"), 
        org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
    sb.append(b64);
    sb.append('.');
    
    JSONObject algO = new JSONObject(mPKAlgorithm);
    String jwtAlgStr = algO.getString("alg");

    Signature signature = Signature.getInstance(jwtAlgStr);
    signature.initSign(privateKey);
    signature.update(mJsonStr.getBytes("utf-8"));
    byte[] bytes = signature.sign();
    String signed = new String(bytes);
    sb.append(signed);
    return sb.toString();
  }

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
    if ("HS256".equals(jwtAlgStr)) { // HMAC SHA-256
      Mac mac = Mac.getInstance("HMACSHA256");
      mac.init(new SecretKeySpec(passphraseBytes, mac.getAlgorithm()));
      mac.update(stringToSign.getBytes("utf-8"));
      byte[] bytes = mac.doFinal();
      signed = Base64.encodeBytes(bytes, 
          org.xmldap.util.Base64.DONT_BREAK_LINES | org.xmldap.util.Base64.URL);
    } else {
      throw new NoSuchAlgorithmException("JWT shared secret" + jwtAlgStr);
    }
    sb.append(signed);
    return sb.toString();
  }
}
