package org.xmldap.infocard;

import nu.xom.Attribute;
import nu.xom.Element;
import nu.xom.Elements;

import org.json.JSONException;
import org.json.JSONObject;
import org.xmldap.exceptions.ParsingException;
import org.xmldap.exceptions.SerializationException;
import org.xmldap.ws.WSConstants;

public class UserCredential {
    public static final String USERNAME = "UserNamePasswordAuthenticate";
    public static final String SELF_ISSUED = "SelfIssuedAuthenticate";
    public static final String X509 = "X509V3Authenticate";
    public static final String KERB = "KerberosV5Authenticate";


    private String authType = USERNAME;
    
    private String hint = null;
    
	private String userName = null;
    private String ppi = null;
    private String x509Hash = null;
    private String kerberosServicePrincipalName = null;
    
	public UserCredential(Element elt) throws ParsingException {
		String name = elt.getLocalName();
		if ("UserCredential".equals(name)) {
			Elements elts = elt.getChildElements("DisplayCredentialHint", WSConstants.INFOCARD_NAMESPACE);
			if (elts.size() == 1) {
				Element displayCredentialHintElt = elts.get(0);
				hint = displayCredentialHintElt.getValue();
			} else {
				if (elts.size() > 1) {
					throw new ParsingException("Expected zero or one UserCredential but found" + elts.size());
				}
				// else size == 0. OK
				hint = null;
			}
			
			elts = elt.getChildElements("UsernamePasswordCredential", WSConstants.INFOCARD_NAMESPACE);
			if (elts.size() == 1) {
				authType = USERNAME;
				Element usernamePasswordCredential = elts.get(0);
				Element usernameElt = usernamePasswordCredential.getFirstChildElement("Username", WSConstants.INFOCARD_NAMESPACE);
				if (usernameElt != null) {
					userName = usernameElt.getValue();
				} else {
					throw new ParsingException("Expected Username");
				}
			} else {
				elts = elt.getChildElements("KerberosV5Credential", WSConstants.INFOCARD_NAMESPACE);
				if (elts.size() == 1) {
					authType = KERB;
				} else {
					elts = elt.getChildElements("X509V3Credential", WSConstants.INFOCARD_NAMESPACE);
					if (elts.size() == 1) {
						authType = X509;
						Element x509V3Credential = elts.get(0);
						elts = x509V3Credential.getChildElements("X509Data", WSConstants.DSIG_NAMESPACE);
						if (elts.size() == 1) {
							Element x509Data = elts.get(0);
							elts = x509Data.getChildElements("KeyIdentifier", WSConstants.WSSE_NAMESPACE_OASIS_10);
							if (elts.size() == 1) {
								Element keyIdentifier = elts.get(0);
								// TODO check ValueType and EncodingType
								x509Hash = keyIdentifier.getValue();
							} else {
								throw new ParsingException("Expected one KeyIdentifier but found: " + elts.size());
							}
						} else {
							throw new ParsingException("Expected one X509Data but found: " + elts.size());
						}
					} else {
						elts = elt.getChildElements("SelfIssuedCredential", WSConstants.INFOCARD_NAMESPACE);
						if (elts.size() == 1) {
							authType = SELF_ISSUED;
							Element selfIssuedCredential = elts.get(0);
							elts = selfIssuedCredential.getChildElements("PrivatePersonalIdentifier", WSConstants.INFOCARD_NAMESPACE);
							if (elts.size() == 1) {
								Element privatePersonalIdentifier = elts.get(0);
								this.ppi = privatePersonalIdentifier.getValue();
							} else {
								throw new ParsingException("Expected one PrivatePersonalIdentifier but found: " + elts.size());
							}
						} else {
							throw new ParsingException("Expected one of UsernamePasswordCredential, KerberosV5Credential, X509V3Credential or SelfIssuedCredential");
						}
					}
					
				}
				
			}
			

		} else {
			throw new ParsingException("Expected UserCredential but found" + name);
		}
  }
  
  public UserCredential(JSONObject json) throws JSONException {
    authType = json.optString("Type", null);
    hint = json.optString("Hint", null);
    
    json.put("Type", authType);
    if (USERNAME.equals(authType)) {
      userName = json.getString("Username");
    } else if (KERB.equals(authType)) {
      // TODO
      throw new JSONException("Unsupported Authentication Type: " + authType);
    } else if (SELF_ISSUED.equals(authType)) {
      ppi = json.getString("PPID");
      json.put("PPID", ppi);
    } else if (X509.equals(authType)) {
      x509Hash = json.getString("X509Hash");
    } else {
      throw new JSONException("Unsupported Authentication Type: " + authType);
    }
  }
  
  public UserCredential(String authType, String value) {
		setAuthType(authType, value);
	}
	
    public String getHint() {
		return hint;
	}

	public void setHint(String hint) {
		this.hint = hint;
	}

    public String getAuthType() {
        return authType;
    }

    public String getPPI() {
        return ppi;
    }

    // use public void setAuthType(TokenServiceReference.SELF_ISSUED, String value)
    private void setPPI(String ppi) {
        this.ppi = ppi;
    }

    public String getKerberosServicePrincipalName() {
        return kerberosServicePrincipalName;
    }

    // use public void setAuthType(TokenServiceReference.KERB, String value)
    private void setKerberosServicePrincipalName(String kerberosServicePrincipalName) {
        this.kerberosServicePrincipalName = kerberosServicePrincipalName;
    }

    public String getX509Hash() {
        return x509Hash;
    }

    // use public void setAuthType(TokenServiceReference.X509, String value)
    private void setX509Hash(String x509Hash) {
        this.x509Hash = x509Hash;
    }

    public String getUserName() {
        return userName;
    }

    // use public void setAuthType(TokenServiceReference.USERNAME, String value)
    private void setUserName(String userName) {
        this.userName = userName;
    }

//    public void setCert(X509Certificate cert) {
//        this.cert = cert;
//    }

    protected void setAuthType(String authType, String value) {
    	if (UserCredential.USERNAME.equals(authType)) {
    		setUserName(value);
    	} else if (UserCredential.KERB.equals(authType)) {
    		setKerberosServicePrincipalName(value);
    	} else if (UserCredential.SELF_ISSUED.equals(authType)) {
    		setPPI(value);
    	} else if (UserCredential.X509.equals(authType)) {
    		setX509Hash(value);
    	} else {
    		throw new IllegalArgumentException("undefined authentication type (" + authType + ")");
    	}
		this.authType = authType;
    }

    public JSONObject toJSON() throws SerializationException {
      try {
        JSONObject json = new JSONObject();
        json.put("Type", authType);
        if (USERNAME.equals(authType)) {
          json.put("Username", userName);
        } else if (KERB.equals(authType)) {
          // TODO
          throw new SerializationException("Unsupported Authentication Type: " + authType);
        } else if (SELF_ISSUED.equals(authType)) {
          json.put("PPID", ppi);
        } else if (X509.equals(authType)) {
          json.put("X509Hash", x509Hash);
        } else {
          throw new SerializationException("Unsupported Authentication Type: " + authType);
        }
        if (hint != null) {
          json.put("Hint", hint);
        }
        return json;
      } catch (JSONException e) {
        throw new SerializationException(e);
      }

    }

    public Element serialize() throws SerializationException {
        Element userCredential = new Element(WSConstants.INFOCARD_PREFIX + ":UserCredential", WSConstants.INFOCARD_NAMESPACE);
        if (USERNAME.equals(authType)) {
	        Element displayCredentialHint = new Element(WSConstants.INFOCARD_PREFIX + ":DisplayCredentialHint", WSConstants.INFOCARD_NAMESPACE);
	        if (hint != null) {
	        	displayCredentialHint.appendChild(hint);
	        } else {
	        	displayCredentialHint.appendChild("Please enter your username and password.");
	        }
	        userCredential.appendChild(displayCredentialHint);
	
	        Element credential = new Element(WSConstants.INFOCARD_PREFIX + ":UsernamePasswordCredential", WSConstants.INFOCARD_NAMESPACE);
	        Element username = new Element(WSConstants.INFOCARD_PREFIX + ":Username", WSConstants.INFOCARD_NAMESPACE);
	        username.appendChild(userName);
	        credential.appendChild(username);
	        userCredential.appendChild(credential);
        } else if (KERB.equals(authType)) {
	        Element displayCredentialHint = new Element(WSConstants.INFOCARD_PREFIX + ":DisplayCredentialHint", WSConstants.INFOCARD_NAMESPACE);
	        if (hint != null) {
	        	displayCredentialHint.appendChild(hint);
	        } else {
		        displayCredentialHint.appendChild("Enter your kerberos credentials");
	        }
	        userCredential.appendChild(displayCredentialHint);
	        // <ic:KerberosV5Credential />
	        Element credential = new Element(WSConstants.INFOCARD_PREFIX + ":KerberosV5Credential", WSConstants.INFOCARD_NAMESPACE);
	        userCredential.appendChild(credential);
	        /* To enable the service requester to obtain a Kerberos v5 service ticket for the IP/STS, the endpoint reference of the IP/STS 
	         * in the information card or in the metadata retrieved from it must include a 'service principal name' identity claim under 
	         * the wsid:Identity tag as defined in [Addressing-Ext]. http://www.w3.org/TR/2005/CR-ws-addr-core-20050817/
	         */
        } else if (SELF_ISSUED.equals(authType)) {
	        Element displayCredentialHint = new Element(WSConstants.INFOCARD_PREFIX + ":DisplayCredentialHint", WSConstants.INFOCARD_NAMESPACE);
	        if (hint != null) {
	        	displayCredentialHint.appendChild(hint);
	        } else {
		        displayCredentialHint.appendChild("Choose a self-asserted card");
	        }
	        userCredential.appendChild(displayCredentialHint);
        	/*
	        	  <ic:SelfIssuedCredential>
	        	    <ic:PrivatePersonalIdentifier>
	        	      xs:base64Binary 
	        	    </ic:PrivatePersonalIdentifier>
	        	  </ic:SelfIssuedCredential>
        	 */
	        Element credential = new Element(WSConstants.INFOCARD_PREFIX + ":SelfIssuedCredential", WSConstants.INFOCARD_NAMESPACE);
	        Element credentialValue = new Element(WSConstants.INFOCARD_PREFIX + ":PrivatePersonalIdentifier", WSConstants.INFOCARD_NAMESPACE);
	        credentialValue.appendChild(ppi);
	        credential.appendChild(credentialValue);
	        userCredential.appendChild(credential);
	        //System.out.println(userCredential.toXML());
        } else if (X509.equals(authType)) {
        	/*
  				  <ic:DisplayCredentialHint> xs:string </ic:DisplayCredentialHint>
  				  <ic:X509V3Credential>
				    <ds:X509Data>
				      <wsse:KeyIdentifier
				        ValueType="http://docs.oasis-open.org/wss/2004/xx/oasis-2004xx-wss-soap-message-security-1.1#ThumbprintSHA1"
				        EncodingType="http://docs.oasis-open.org/wss/2004/xx/oasis-2004xx-wss-soap-message-security-1.1#Base64Binary">
				        xs:base64binary
				      </wsse:KeyIdentifier>
				    </ds:X509Data>
				  </ic:X509V3Credential>
        	 */
	        Element displayCredentialHint = new Element(WSConstants.INFOCARD_PREFIX + ":DisplayCredentialHint", WSConstants.INFOCARD_NAMESPACE);
	        if (hint != null) {
	        	displayCredentialHint.appendChild(hint);
	        } else {
		        displayCredentialHint.appendChild("Choose a certificate");
	        }
	        userCredential.appendChild(displayCredentialHint);
	
	        Element credential = new Element(WSConstants.INFOCARD_PREFIX + ":X509V3Credential", WSConstants.INFOCARD_NAMESPACE);
	        Element x509Data = new Element(WSConstants.DSIG_PREFIX + ":X509Data", WSConstants.DSIG_NAMESPACE);
	        Element keyIdentifier = new Element(WSConstants.WSSE_PREFIX + ":KeyIdentifier", WSConstants.WSSE_NAMESPACE_OASIS_10);
	        Attribute valueType = new Attribute("ValueType", WSConstants.WSSE_OASIS_XX_THUMBPRINTSHA1);
	        Attribute encodingType = new Attribute("EncodingType", WSConstants.WSSE_OASIS_XX_BASE64BINARY);
	        keyIdentifier.addAttribute(valueType);
	        keyIdentifier.addAttribute(encodingType);
	        keyIdentifier.appendChild(x509Hash);
	        x509Data.appendChild(keyIdentifier);
	        credential.appendChild(x509Data);
	        userCredential.appendChild(credential);
        } else {
        	throw new SerializationException("unsupported authentication type:" + authType);
        }
        return userCredential;
    }

}
