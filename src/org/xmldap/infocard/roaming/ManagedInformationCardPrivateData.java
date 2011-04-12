package org.xmldap.infocard.roaming;

import java.util.Random;

import nu.xom.Element;
import nu.xom.Elements;

import org.xmldap.exceptions.ParsingException;
import org.xmldap.util.Base64;
import org.xmldap.ws.WSConstants;

public class ManagedInformationCardPrivateData 
		extends InformationCardPrivateData implements Comparable<InformationCardPrivateData>  {
	String masterKey = null;

	public ManagedInformationCardPrivateData(Element managedInformationCardPrivateData) throws ParsingException {
	   	if ("InformationCardPrivateData".equals(managedInformationCardPrivateData.getLocalName())) {
	   		Elements elts = managedInformationCardPrivateData.getChildElements("MasterKey", WSConstants.INFOCARD_NAMESPACE);
	   		if (elts.size() != 1) {
	   			throw new ParsingException("Found " + elts.size() + " MasterKey elements in  ic:InformationCardPrivateData");
	   		} else {
	   			Element masterkeyElement = elts.get(0);
	   			masterKey = masterkeyElement.getValue();
	   		}
	   	} else {
	   		throw new ParsingException("expected ic:InformationCardPrivateData");
	   	}
	}
	
	public ManagedInformationCardPrivateData(String masterKeyBase64) {
		masterKey = masterKeyBase64;
	}
	
	public ManagedInformationCardPrivateData() {
    	Random random = new Random();
    	byte[] bytes = new byte[256];
    	random.nextBytes(bytes);
    	this.masterKey = Base64.encodeBytesNoBreaks(bytes);
	}

	public Element serialize() {
        Element informationCardPrivateData = new Element("InformationCardPrivateData", WSConstants.INFOCARD_NAMESPACE);

        Element masterKeyElt = new Element("MasterKey", WSConstants.INFOCARD_NAMESPACE);
        masterKeyElt.appendChild(masterKey);
        informationCardPrivateData.appendChild(masterKeyElt);
        return informationCardPrivateData;
	}

	@Override
	public int compareTo(InformationCardPrivateData obj) {
    	if (this == obj) return 0;
    	
    	ManagedInformationCardPrivateData anObj = (ManagedInformationCardPrivateData)obj;
    	int comparison = masterKey.compareTo(anObj.masterKey);
    	return comparison;
	}
}
