package org.xmldap.json;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;

import org.json.JSONException;
import org.json.JSONObject;

public class WebTokenCipherSpi extends CipherSpi {
private Key mKey;
private JSONObject mJwtHeader;

public int getEncKeyLength() throws IOException, JSONException, NoSuchAlgorithmException {
  String jwtEncStr = (String) mJwtHeader.get("enc");
  return WebToken.getEncKeyLength(jwtEncStr);
}

int getIntKeyLength() throws JSONException, NoSuchAlgorithmException {
  String jwtIntStr = (String) mJwtHeader.get("int");
  return WebToken.getIntKeyLength(jwtIntStr);
}

boolean isAEADenc() throws NoSuchAlgorithmException, JSONException {
  String jwtEncStr = (String) mJwtHeader.get("enc");
  return WebToken.isAEADenc(jwtEncStr);
}

int getLargerKeylength() throws NoSuchAlgorithmException, JSONException, IOException {
  if (isAEADenc()) {
    // if there is an int then it is ignored
    return getEncKeyLength();
  }
  return Math.max(getEncKeyLength(), getIntKeyLength());
}


@Override
protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException,
    BadPaddingException {
  // TODO Auto-generated method stub
  return null;
}

@Override
protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
    throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
  // TODO Auto-generated method stub
  return 0;
}

@Override
protected int engineGetBlockSize() {
  // TODO Auto-generated method stub
  return 0;
}

@Override
protected byte[] engineGetIV() {
  // TODO Auto-generated method stub
  return null;
}

@Override
protected int engineGetOutputSize(int inputLen) {
  // TODO Auto-generated method stub
  return 0;
}

@Override
protected AlgorithmParameters engineGetParameters() {
  // TODO Auto-generated method stub
  return null;
}

@Override
protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
  // TODO Auto-generated method stub

}

@Override
protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
    throws InvalidKeyException, InvalidAlgorithmParameterException {
  if (!(params instanceof JsonCryptoParameterSpec)) {
    throw new InvalidAlgorithmParameterException("JsonCryptoParameterSpec needed");
  }
  // FIXME
}

@Override
protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
    throws InvalidKeyException, InvalidAlgorithmParameterException {
  try {
    JsonCryptoParameterSpec spec = params.getParameterSpec(JsonCryptoParameterSpec.class);
    mJwtHeader = new JSONObject(spec.mJwtHeader);

    if (opmode == Cipher.ENCRYPT_MODE) {
      String jwtAlgStr = mJwtHeader.getString("alg");
      if (WebToken.ENC_ALG_RSA1_5.equals(jwtAlgStr) || WebToken.ENC_ALG_RSA_OAEP.equals(jwtAlgStr)) {
        if (key instanceof RSAPublicKey) {
          mKey = key;
        } else {
          throw new InvalidKeyException("need a RSAPublicKey if alg="+jwtAlgStr);
        }
      } else if (WebToken.ENC_ALG_A128KW.equals(jwtAlgStr) || WebToken.ENC_ALG_A256KW.equals(jwtAlgStr)) {
        if (key instanceof SecretKey) {
          if ("AES".equals(key.getAlgorithm()) || "RAW".equals(key.getAlgorithm())) {
            mKey = key;
          } else {
            throw new InvalidKeyException("Need a SecretKey format of RAW or AES if alg="+jwtAlgStr);
          }
        } else {
          throw new InvalidKeyException("Need a SecretKey if alg="+jwtAlgStr);
        }
      } else {
        throw new InvalidAlgorithmParameterException("unsupported algorithm: " + jwtAlgStr);
      }
    } else if (opmode == Cipher.DECRYPT_MODE) {

      JSONObject header = new JSONObject(spec.mJwtHeader);
      String jwtAlgStr = header.getString("alg");
      if (WebToken.ENC_ALG_RSA1_5.equals(jwtAlgStr) || WebToken.ENC_ALG_RSA_OAEP.equals(jwtAlgStr)) {
        if (key instanceof RSAPrivateKey) {
          mKey = key;
        } else {
          throw new InvalidKeyException("need a RSAPrivateKey if alg="+jwtAlgStr);
        }
      } else if (WebToken.ENC_ALG_A128KW.equals(jwtAlgStr) || WebToken.ENC_ALG_A256KW.equals(jwtAlgStr)) {
        if (key instanceof SecretKey) {
          if ("AES".equals(key.getAlgorithm()) || "RAW".equals(key.getAlgorithm())) {
            mKey = key;
          } else {
            throw new InvalidKeyException("Need a SecretKey format of RAW or AES if alg="+jwtAlgStr);
          }
        } else {
          throw new InvalidKeyException("Need a SecretKey if alg="+jwtAlgStr);
        }
      } else {
        throw new InvalidAlgorithmParameterException("unsupported algorithm: " + jwtAlgStr);
      }
    } else {
      throw new RuntimeException("invalid mode: " + opmode);
    }
  } catch (InvalidParameterSpecException e) {
    throw new InvalidAlgorithmParameterException(e);
  } catch (JSONException e) {
    throw new InvalidAlgorithmParameterException(e);
  }
}

@Override
protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
  // TODO Auto-generated method stub

}

@Override
protected void engineSetPadding(String padding) throws NoSuchPaddingException {
  // TODO Auto-generated method stub

}

@Override
protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
  // TODO Auto-generated method stub
  return null;
}

@Override
protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
    throws ShortBufferException {
  // TODO Auto-generated method stub
  return 0;
}
}
