package org.xmldap.json;

import java.security.spec.AlgorithmParameterSpec;


public class JsonCryptoParameterSpec implements AlgorithmParameterSpec {
  String mJwtHeader;
  public JsonCryptoParameterSpec(String jwtHeader) {
    mJwtHeader = jwtHeader;
  }
}
