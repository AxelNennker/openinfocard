package org.xmldap.infocard.roaming;

import nu.xom.Element;
import nu.xom.Elements;

import org.xmldap.exceptions.ParsingException;
import org.xmldap.ws.WSConstants;

public class InformationCardReference implements Comparable<InformationCardReference>{
	String cardId = null;
	long cardVersion = 1;
	
	public InformationCardReference(Element informationCardReferenceElement) throws ParsingException {
		Elements elts = informationCardReferenceElement.getChildElements("CardId", WSConstants.INFOCARD_NAMESPACE);
		if (elts.size() == 1) {
			Element cardIdElement = elts.get(0);
			cardId = cardIdElement.getValue();
		} else {
			throw new ParsingException("found " + elts.size() + " elements of type CardId");
		}
		elts = informationCardReferenceElement.getChildElements("CardVersion", WSConstants.INFOCARD_NAMESPACE);
		if (elts.size() == 1) {
			Element cardVersionElement = elts.get(0);
			cardVersion = Integer.valueOf(cardVersionElement.getValue()).longValue();
		} else {
			throw new ParsingException("found " + elts.size() + " elements of type CardVersion");
		}
	}
	
	public InformationCardReference(String cardId, long cardVersion) {
		setCardId(cardId);
		setCardVersion(cardVersion);
	}
	
	public Element serialize() {
        Element informationCardReferenceElement = new Element(WSConstants.INFOCARD_PREFIX + ":InformationCardReference", WSConstants.INFOCARD_NAMESPACE);
        Element cardIdElement = new Element(WSConstants.INFOCARD_PREFIX + ":CardId", WSConstants.INFOCARD_NAMESPACE);
        cardIdElement.appendChild(cardId);
        Element cardVersionElement = new Element(WSConstants.INFOCARD_PREFIX + ":CardVersion", WSConstants.INFOCARD_NAMESPACE);
        cardVersionElement.appendChild(String.valueOf(cardVersion));
        informationCardReferenceElement.appendChild(cardIdElement);
        informationCardReferenceElement.appendChild(cardVersionElement);
        return informationCardReferenceElement;
	}

	public String getCardId() {
		return cardId;
	}

	public void setCardId(String cardId) {
		this.cardId = cardId;
	}

	public long getCardVersion() {
		return cardVersion;
	}

	public void setCardVersion(long cardVersion) {
		if (cardVersion < 1) {
			throw new IllegalArgumentException("CardVersion must be at least 1");
		}
		this.cardVersion = cardVersion;
	}

	@Override
	public int compareTo(InformationCardReference obj) {
		if (this == obj) return 0;
		
		int comparison = cardId.compareTo(obj.cardId);
    	if (comparison != 0) return comparison;

    	if (this.cardVersion < obj.cardVersion) return -1;
    	if (this.cardVersion > obj.cardVersion) return 1;
    	
		return 0;
	}
}
