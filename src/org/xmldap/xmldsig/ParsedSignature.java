package org.xmldap.xmldsig;

import java.io.IOException;

import nu.xom.Element;

import org.xmldap.exceptions.ParsingException;
import org.xmldap.ws.WSConstants;

public class ParsedSignature {
	ParsedSignedInfo parsedSignedInfo = null;
	String signatureValue = null;
	ParsedKeyInfo parsedKeyInfo = null;
	byte[] signedInfoCanonicalBytes = null;
	
	public ParsedSignature(Element signature) throws IOException, ParsingException {
		Element signedInfo = signature.getFirstChildElement("SignedInfo", WSConstants.DSIG_NAMESPACE);
		parsedSignedInfo = new ParsedSignedInfo(signedInfo);
		signatureValue = signature.getFirstChildElement("SignatureValue", WSConstants.DSIG_NAMESPACE).getValue();
		Element keyInfo = signature.getFirstChildElement("KeyInfo", WSConstants.DSIG_NAMESPACE);
		parsedKeyInfo = new ParsedKeyInfo(keyInfo);
		signedInfoCanonicalBytes = parsedSignedInfo.getCanonicalBytes();
	}
	
//	private boolean validate(Element root) {
//		return false;
//	}

	public byte[] getSignedInfoCanonicalBytes() throws IOException {
		return signedInfoCanonicalBytes;
	}

	/**
	 * @return the parsedKeyInfo
	 */
	public ParsedKeyInfo getParsedKeyInfo() {
		return parsedKeyInfo;
	}

	/**
	 * @return the parsedSignedInfo
	 */
	public ParsedSignedInfo getParsedSignedInfo() {
		return parsedSignedInfo;
	}

	/**
	 * @return the signatureValue
	 */
	public String getSignatureValue() {
		return signatureValue;
	}
}
