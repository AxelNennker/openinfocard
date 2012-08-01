package org.xmldap.json;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.IvParameterSpec;

import org.json.JSONException;
import org.json.JSONObject;

public abstract class JsonCryptoAlgorithmParameters extends AlgorithmParametersSpi {
  JSONObject mHeader;
  String mHeaderStr;

  protected AlgorithmParameterSpec engineGetParameterSpec(Class paramSpec) throws InvalidParameterSpecException {
    if (paramSpec == null) {
      throw new NullPointerException("argument to getParameterSpec must not be null");
    }

    return localEngineGetParameterSpec(paramSpec);
  }

  protected abstract AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec)
      throws InvalidParameterSpecException;

  public static class RSA15 extends JsonCryptoAlgorithmParameters {    
    protected byte[] engineGetEncoded() {
      return mHeaderStr.getBytes(); // everything needed is in the JWT already
    }

    protected byte[] engineGetEncoded(String format) {
      return null; // everything needed is in the JWT already
    }

    protected AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec) throws InvalidParameterSpecException {
      if (paramSpec == JsonCryptoParameterSpec.class) {
        return new JsonCryptoParameterSpec(mHeaderStr);
      }

      throw new InvalidParameterSpecException("unknown parameter spec.");
    }

    protected void engineInit(
            AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException
        {
            if (!(paramSpec instanceof JsonCryptoParameterSpec))
            {
                throw new InvalidParameterSpecException("JsonCryptoAlgorithmParameters required");
            }

            JsonCryptoParameterSpec    spec = (JsonCryptoParameterSpec)paramSpec;

            try {
              this.mHeader = new JSONObject(spec.mJwtHeader);
            } catch (JSONException e) {
              throw new InvalidParameterSpecException(e.getMessage());
            }
            this.mHeaderStr = new String(spec.mJwtHeader);
        }

    protected void engineInit(byte[] params) throws IOException {
      try {
        this.mHeaderStr = new String(params);
        this.mHeader = new JSONObject(mHeaderStr);
      } catch (JSONException e) {
        throw new IOException(e);
      }
    }

    protected void engineInit(byte[] params, String format) throws IOException {
      if ("RAW".equals(format)) {
        IvParameterSpec    spec = new IvParameterSpec(params);
        try {
          engineInit(spec);
        } catch (InvalidParameterSpecException e) {
          throw new IOException(e);
        }
        return;
      }

      throw new IOException("Unknown parameters format: " + format);
    }

    protected String engineToString() {
      return "JSONCrypto Parameters";
    }
  }

}
