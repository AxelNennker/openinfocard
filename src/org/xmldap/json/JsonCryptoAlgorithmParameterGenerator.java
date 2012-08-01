package org.xmldap.json;

import java.security.AlgorithmParameterGeneratorSpi;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public class JsonCryptoAlgorithmParameterGenerator extends AlgorithmParameterGeneratorSpi {
  JsonCryptoParameterSpec mParamSpec; 
  
  @Override
  protected AlgorithmParameters engineGenerateParameters() {
    JsonCryptoProvider provider = new JsonCryptoProvider();
    AlgorithmParameters algorithmParameters;
    try {
      algorithmParameters = AlgorithmParameters.getInstance("RSA15", provider);
      algorithmParameters.init(mParamSpec);
      return algorithmParameters;
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (InvalidParameterSpecException e) {
      e.printStackTrace();
    }
    return null;
  }

  @Override
  protected void engineInit(int size, SecureRandom random) {
    throw new RuntimeException("use the other engineInit");
  }

  @Override
  protected void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random)
      throws InvalidAlgorithmParameterException {
    if (!(genParamSpec instanceof JsonCryptoParameterSpec)) {
      throw new InvalidAlgorithmParameterException();
    }
    mParamSpec = (JsonCryptoParameterSpec)genParamSpec;
  }

}
