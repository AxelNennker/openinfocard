package org.xmldap.xmldsig;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import nu.xom.Element;
import nu.xom.Elements;

import org.xmldap.ws.WSConstants;
import org.xmldap.xml.XmlUtils;

public class ParsedSignedInfo extends SignedInfo {
	String canonicalizationAlgorithm = null;
	String signatureAlgorithm = null;
	List<ParsedReference> parsedReferences = new ArrayList<ParsedReference>();
	byte[] canonicalBytes = null;
	
	public ParsedSignedInfo(Element signedInfo) throws IOException {
		Element canonicalizationMethod = signedInfo.getFirstChildElement("CanonicalizationMethod", WSConstants.DSIG_NAMESPACE);
		canonicalizationAlgorithm = canonicalizationMethod.getAttributeValue("Algorithm");
		Element signatureMethod = signedInfo.getFirstChildElement("SignatureMethod", WSConstants.DSIG_NAMESPACE);
		signatureAlgorithm = signatureMethod.getAttributeValue("Algorithm");
		Elements references = signedInfo.getChildElements("Reference", WSConstants.DSIG_NAMESPACE);
		for (int i=0; i<references.size(); i++) {
			Element reference = references.get(i);
			ParsedReference parsedReference = new ParsedReference(reference);
			parsedReferences.add(parsedReference);
		}
		canonicalBytes = XmlUtils.canonicalize(signedInfo, canonicalizationAlgorithm);
	}
	
	public String getCanonicalizationAlgorithm() {
		return canonicalizationAlgorithm;
	}
	public String getSignatureAlgorithm() {
		return signatureAlgorithm;
	}
	public List<ParsedReference> getReferences() {
		return parsedReferences;
	}
	public byte[] getCanonicalBytes() {
		return canonicalBytes;
	}
	
}
