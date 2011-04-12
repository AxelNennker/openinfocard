/*
 * Copyright (c) 2006, Chuck Mortimore - xmldap.org
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the names xmldap, xmldap.org, xmldap.com nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.xmldap.infocard.roaming;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Iterator;
import java.util.SortedSet;
import java.util.TreeSet;

import nu.xom.Document;
import nu.xom.Element;
import nu.xom.Elements;
import nu.xom.ParsingException;
import nu.xom.ValidityException;

import org.xmldap.exceptions.SerializationException;
import org.xmldap.util.XmlFileUtil;
import org.xmldap.ws.WSConstants;

//<ic:RoamingStore>
//<ic:RoamingInformationCard> +
//  <ic:InformationCardMetaData>
//    [Information Card]
//    <ic:IsSelfIssued> xs:boolean </ic:IsSelfIssued>
//    <ic:PinDigest> xs:base64Binary </ic:PinDigest> ?
//    <ic:HashSalt> xs:base64Binary </ic:HashSalt>
//    <ic:TimeLastUpdated> xs:dateTime </ic:TimeLastUpdated>
//    <ic:IssuerId> xs:base64Binary </ic:IssuerId>
//    <ic:IssuerName> xs:string </ic:IssuerName>
//    <ic:BackgroundColor> xs:int </ic:BackgroundColor>
//  </ic:InformationCardMetaData>
//  <ic:InformationCardPrivateData> ?
//    <ic:MasterKey> xs:base64Binary </ic:MasterKey>
//    <ic:ClaimValueList> ?
//      <ic:ClaimValue Uri="xs:anyURI" ...> +
//        <ic:Value> xs:string </ic:Value>
//      </ic:ClaimValue>
//    </ic:ClaimValueList>
//  </ic:InformationCardPrivateData>
//</ic:RoamingInformationCard>
//</ic:RoamingStore>

public class RoamingStore implements org.xmldap.xml.Serializable {

    private SortedSet<RoamingInformationCard> roamingInformationCards = null;

    public RoamingStore() {
        roamingInformationCards = new TreeSet<RoamingInformationCard>();
    }

    public RoamingStore(SortedSet<RoamingInformationCard> roamingInformationCards) {
        this.roamingInformationCards = roamingInformationCards;
    }

    public RoamingStore(String roamingStoreStr) throws ValidityException, IOException, ParsingException, org.xmldap.exceptions.ParsingException {
    	this(XmlFileUtil.readXml(new ByteArrayInputStream(roamingStoreStr.getBytes())));
    }

    public boolean equals(Object obj) {
		if (this == obj) return true;
		if ((obj == null) || (obj.getClass() != this.getClass())) return false;
		RoamingStore test = (RoamingStore) obj;
		if (roamingInformationCards == test.roamingInformationCards) return true;
		if (roamingInformationCards != null) {
			if (roamingInformationCards.size() != test.roamingInformationCards.size()) return false;
			Iterator<RoamingInformationCard> thisIter=roamingInformationCards.iterator();
			Iterator<RoamingInformationCard> thatIter=test.roamingInformationCards.iterator();
			while ( thisIter.hasNext() && thatIter.hasNext() ) {
				RoamingInformationCard thisElt = thisIter.next();
				RoamingInformationCard thatElt = thatIter.next();
				if (!thisElt.equals(thatElt)) return false;
			}
		}
		return true;
	}

    public int hashCode() {
		int hash = 7;
		hash = 31 * hash + (null == roamingInformationCards ? 0 : roamingInformationCards.hashCode());
		return hash;
	}

    
    public RoamingStore(Document roamingStoreDoc) throws IOException, org.xmldap.exceptions.ParsingException, ParsingException {
    	Element root = roamingStoreDoc.getRootElement();
    	if ("RoamingStore".equals(root.getLocalName())) {
    		Elements roamingCardsElts = root.getChildElements("RoamingInformationCard", WSConstants.INFOCARD_NAMESPACE);
    		for (int i=0; i<roamingCardsElts.size(); i++) {
    			Element roamingCardElt = roamingCardsElts.get(i);
    			if (roamingInformationCards == null) {
    				roamingInformationCards = new TreeSet<RoamingInformationCard>();
    			}
    			RoamingInformationCard roamingInformationCard = new RoamingInformationCard(roamingCardElt);
    			roamingInformationCards.add(roamingInformationCard);
    		}
    	} else {
    		throw new ParsingException("RoamingStore expected: " + root.getLocalName());
    	}
    }

    public void addRoamingInformationCard(RoamingInformationCard ric) {

        roamingInformationCards.add(ric);

    }

    public SortedSet<RoamingInformationCard> getRoamingInformationCards() {

        return roamingInformationCards;

    }

    private Element getRoamingStore() throws SerializationException {

        Element roamingStore = new Element("RoamingStore", WSConstants.INFOCARD_NAMESPACE);
        Iterator<RoamingInformationCard> cards = roamingInformationCards.iterator();
        while (cards.hasNext()) {
            RoamingInformationCard card  = (RoamingInformationCard) cards.next();
            roamingStore.appendChild(card.serialize());
        }

        return roamingStore;
    }


    public String toXML() throws SerializationException {

        Element keyInfo = serialize();
        return keyInfo.toXML();

    }

    public Element serialize() throws SerializationException {

        return getRoamingStore();

    }
}
