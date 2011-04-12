package org.xmldap.infocard.roaming;

import java.io.IOException;

import nu.xom.Element;
import nu.xom.ValidityException;

import org.xmldap.exceptions.ParsingException;
import org.xmldap.exceptions.SerializationException;
import org.xmldap.ws.WSConstants;

public class RoamingInformationCard implements org.xmldap.xml.Serializable, Comparable<RoamingInformationCard> {
//	  <ic:RoamingInformationCard> +
//	    <ic:InformationCardMetaData>
//	      [Information Card]
//	      <ic:IsSelfIssued> xs:boolean </ic:IsSelfIssued>
//	      <ic:PinDigest> xs:base64Binary </ic:PinDigest> ?
//	      <ic:HashSalt> xs:base64Binary </ic:HashSalt>
//	      <ic:TimeLastUpdated> xs:dateTime </ic:TimeLastUpdated>
//	      <ic:IssuerId> xs:base64Binary </ic:IssuerId>
//	      <ic:IssuerName> xs:string </ic:IssuerName>
//	      <ic:BackgroundColor> xs:int </ic:BackgroundColor>
//	    </ic:InformationCardMetaData>
//	    <ic:InformationCardPrivateData> ?
//	      <ic:MasterKey> xs:base64Binary </ic:MasterKey>
//	      <ic:ClaimValueList> ?
//	        <ic:ClaimValue Uri="xs:anyURI" ...> +
//	          <ic:Value> xs:string </ic:Value>
//	        </ic:ClaimValue>
//	      </ic:ClaimValueList>
//	    </ic:InformationCardPrivateData>
//	  </ic:RoamingInformationCard>

	InformationCardMetaData informationCardMetaData = null;
	InformationCardPrivateData informationCardPrivateData = null;
	
  public InformationCardMetaData getInformationCardMetaData() {
    return informationCardMetaData;
  }
  
  public InformationCardPrivateData getInformationCardPrivateData() {
    return informationCardPrivateData;
  }
  
    public boolean equals(Object obj) {
		if (this == obj) return true;
		if ((obj == null) || (obj.getClass() != this.getClass())) return false;
		RoamingInformationCard test = (RoamingInformationCard) obj;
		return (this.compareTo(test) == 0);
	}

    public int hashCode() {
		int hash = 7;
		hash = 31 * hash + (null == informationCardMetaData ? 0 : informationCardMetaData.hashCode());
		hash = 31 * hash + (null == informationCardPrivateData ? 0 : informationCardPrivateData.hashCode());
		return hash;
	}

    public int compareTo(RoamingInformationCard obj) {
    	if (this == obj) return 0;
    	
    	int comparison = informationCardMetaData.compareTo(obj.informationCardMetaData);
    	if (comparison != 0) return comparison;
    	
    	if (informationCardPrivateData != null) {
    		if (informationCardPrivateData instanceof SelfIssuedInformationCardPrivateData) {
    			SelfIssuedInformationCardPrivateData thisSelfIssuedInformationCardPrivateData = (SelfIssuedInformationCardPrivateData)informationCardPrivateData;
    			SelfIssuedInformationCardPrivateData thatSelfIssuedInformationCardPrivateData = (SelfIssuedInformationCardPrivateData)obj.informationCardPrivateData;
    	    	comparison = thisSelfIssuedInformationCardPrivateData.compareTo(thatSelfIssuedInformationCardPrivateData);
    	    	return comparison;
    		}
    		if (informationCardPrivateData instanceof ManagedInformationCardPrivateData) {
    			ManagedInformationCardPrivateData thisManagedInformationCardPrivateData = (ManagedInformationCardPrivateData)informationCardPrivateData;
    			ManagedInformationCardPrivateData thatManagedInformationCardPrivateData = (ManagedInformationCardPrivateData)obj.informationCardPrivateData;
    	    	comparison = thisManagedInformationCardPrivateData.compareTo(thatManagedInformationCardPrivateData);
    	    	return comparison;
    		}
        	throw new ClassCastException();
    	}
    	if (obj.informationCardPrivateData == null) {
    		return 0;
    	} else {
    		return 1;
    	}
    	
    }
    
//    public RoamingInformationCard(InfoCard card) {
//        this.informationCardMetaData.card = card;
//        informationCardPrivateData = new InformationCardPrivateData();
//    }

    public RoamingInformationCard(InformationCardMetaData informationCardMetaData, InformationCardPrivateData informationCardPrivateData) {
    	if (informationCardMetaData.getTokenList() == null) {
    		throw new IllegalArgumentException("SupportedTokenList in information card MUST not be null");
    	}
    	if (informationCardMetaData.getTokenServiceReference() == null) {
    		throw new IllegalArgumentException("TokenServiceList in information card MUST not be null");
    	}
    	
        this.informationCardMetaData = informationCardMetaData;
        this.informationCardPrivateData = informationCardPrivateData;
    }

    public RoamingInformationCard(Element roamingInformationCardElement) throws ValidityException, IOException, ParsingException, ParsingException {
    	Element informationCardMetaDataElement = roamingInformationCardElement.getFirstChildElement("InformationCardMetaData", WSConstants.INFOCARD_NAMESPACE);
    	informationCardMetaData = new InformationCardMetaData(informationCardMetaDataElement);
    	Element informationCardPrivateDataElement = roamingInformationCardElement.getFirstChildElement("InformationCardPrivateData", WSConstants.INFOCARD_NAMESPACE);
    	if (informationCardPrivateDataElement != null) {
    		if (informationCardMetaData.getIsSelfIssued()) {
    			informationCardPrivateData = new SelfIssuedInformationCardPrivateData(informationCardPrivateDataElement);
    		} else {
    			informationCardPrivateData = new ManagedInformationCardPrivateData(informationCardPrivateDataElement);
    		}
    	}
    }

    private Element getRoamingInformationCard() throws SerializationException {

        Element roamingInformationCard = new Element("RoamingInformationCard", WSConstants.INFOCARD_NAMESPACE);

        roamingInformationCard.appendChild(informationCardMetaData.serialize());
        if (informationCardPrivateData != null) {
        	roamingInformationCard.appendChild(informationCardPrivateData.serialize());
        }
        //TODO - I need to come up with a strategy to merge all the card serialization formats into one or two

        return roamingInformationCard;
    }

    
    public String toXML() throws SerializationException {
        Element ric = serialize();
        return ric.toXML();
    }

    public Element serialize() throws SerializationException {
        return getRoamingInformationCard();
    }
}
