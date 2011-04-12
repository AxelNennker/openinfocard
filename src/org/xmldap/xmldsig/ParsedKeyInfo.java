package org.xmldap.xmldsig;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import nu.xom.Element;

import org.xmldap.exceptions.ParsingException;
import org.xmldap.util.Base64;
import org.xmldap.ws.WSConstants;

// <dsig:KeyInfo>
//  <dsig:KeyName>Public Key for C=US, ST=California, L=San Francisco, O=xmldap, OU=infocard selector, CN=firefox</dsig:KeyName>
//  <dsig:KeyValue>
//   <dsig:RSAKeyValue>
//    <dsig:Modulus>ALcns4ngVsyotUe ... 31OAmEtdnF7MZ</dsig:Modulus>
//    <dsig:Exponent>AQAB</dsig:Exponent>
//   </dsig:RSAKeyValue>
//  </dsig:KeyValue>
//  <dsig:X509Data>
//   <dsig:X509Certificate>MIIDjzCCAvigAwIBAgIG ... RPo71Qg6ApCinzllSDoga5zFbSS8pzX</dsig:X509Certificate>
//  </dsig:X509Data>
// </dsig:KeyInfo>

public class ParsedKeyInfo {
	String certificate = null;
	String keyName = null;
	ParsedKeyValue keyValue = null;
	ParsedX509Data x509Data = null;
	public ParsedKeyInfo(Element element) throws ParsingException {
		Element child = element.getFirstChildElement("KeyName", WSConstants.DSIG_NAMESPACE);
		if (child != null) {
			keyName = child.getValue();
		}
		child = element.getFirstChildElement("KeyValue", WSConstants.DSIG_NAMESPACE);
		if (child != null) {
			keyValue = new ParsedKeyValue(child);
		}
		child = element.getFirstChildElement("X509Data", WSConstants.DSIG_NAMESPACE);
		if (child != null) {
			x509Data = new ParsedX509Data(child);
		}
	}
	
	public ParsedX509Data getParsedX509Data() {
		return x509Data;
	}
	
	public ParsedKeyValue getParsedKeyValue() {
		return keyValue;
	}
	
	public BigInteger getModulus() {
		if (x509Data != null) {
			List<X509Certificate> certs = x509Data.getCertificates();
			X509Certificate cert = certs.get(0);
			PublicKey publicKey = cert.getPublicKey();
			RSAPublicKey rsaPublicKey = (RSAPublicKey)publicKey;
			return rsaPublicKey.getModulus();
		} else {
			String mod = keyValue.getModulus();
			return new BigInteger(1, Base64.decode(mod));
		}
	}
	
	public BigInteger getExponent() {
		if (x509Data != null) {
			List<X509Certificate> certs = x509Data.getCertificates();
			X509Certificate cert = certs.get(0);
			PublicKey publicKey = cert.getPublicKey();
			RSAPublicKey rsaPublicKey = (RSAPublicKey)publicKey;
			return rsaPublicKey.getPublicExponent();
		} else {
			String exp = keyValue.getExponent();
			return new BigInteger(1, Base64.decode(exp));
		}

	}
}
