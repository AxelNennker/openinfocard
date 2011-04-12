package org.xmldap.xmldsig;

import java.security.InvalidParameterException;

import nu.xom.Element;

import org.xmldap.ws.WSConstants;

public class ParsedKeyValue {
//  <dsig:KeyValue>
//  <dsig:RSAKeyValue>
//   <dsig:Modulus>ALcns4ngVsyotUe ... 31OAmEtdnF7MZ</dsig:Modulus>
//   <dsig:Exponent>AQAB</dsig:Exponent>
//  </dsig:RSAKeyValue>
// </dsig:KeyValue>
	String modulus = null;
	String exponent = null;
	public ParsedKeyValue(Element element) {
		Element child = element.getFirstChildElement("RSAKeyValue", WSConstants.DSIG_NAMESPACE);
		if (child != null) {
			Element grandChild = child.getFirstChildElement("Modulus", WSConstants.DSIG_NAMESPACE);
			modulus = grandChild.getValue();
			grandChild = child.getFirstChildElement("Exponent", WSConstants.DSIG_NAMESPACE);
			exponent = grandChild.getValue();
		} else {
			throw new InvalidParameterException("Expected child element 'RSAKeyValue'");
		}
	}
	
	public String getModulus() {
		return modulus;
	}
	
	public String getExponent() {
		return exponent;
	}
}
