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

package org.xmldap.infocard;

import java.net.URISyntaxException;
import java.security.PrivateKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import nu.xom.Attribute;
import nu.xom.Element;
import nu.xom.Elements;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.xmldap.exceptions.ParsingException;
import org.xmldap.exceptions.SerializationException;
import org.xmldap.exceptions.SigningException;
import org.xmldap.infocard.policy.SupportedClaim;
import org.xmldap.infocard.policy.SupportedClaimTypeList;
import org.xmldap.infocard.policy.SupportedToken;
import org.xmldap.infocard.policy.SupportedTokenList;
import org.xmldap.infocard.roaming.InformationCardMetaData;
import org.xmldap.infocard.roaming.InformationCardReference;
import org.xmldap.infocard.roaming.ManagedInformationCardPrivateData;
import org.xmldap.infocard.roaming.PrivacyNotice;
import org.xmldap.infocard.roaming.RequireAppliesTo;
import org.xmldap.infocard.roaming.RoamingInformationCard;
import org.xmldap.infocard.roaming.SelfIssuedInformationCardPrivateData;
import org.xmldap.util.XSDDateTime;
import org.xmldap.ws.WSConstants;
import org.xmldap.xml.Serializable;
import org.xmldap.xml.XmlUtils;
import org.xmldap.xmldsig.InfoCardSignature;

/**
 * InfoCard allows you to create an InfoCard, and serialize to XML.
 *
 * @author charliemortimore at gmail.com
 */
public class InfoCard implements Serializable,  Comparable<InfoCard> {

    private X509Certificate[] certChain = null;
    private PrivateKey privateKey = null;
    
    InformationCardReference informationCardReference = null; // required
    private String cardName = null;
    
    ArrayList<String[]> cardImages = null;
    
    private String issuer = null;
    private String timeIssued = null;
    private String timeExpires = null; // optional
    private PrivacyNotice privacyPolicy = null; // optional
    private List<TokenServiceReference> tokenServiceReferenceList = null;
    private SupportedTokenList tokenList = null;
    private SupportedClaimTypeList claimList = null;
    private RequireAppliesTo requireAppliesTo = null; // optional 
    protected String lang = null;

    private String masterSecretBase64 = null; // FIXME unused
    
    boolean requireStrongRecipientIdentity = true;

    String CardType = null;
    String IssuerName = null;

    String frontHtml = null;
    String backHtml = null;
    
    Map<String, String> issuerInformation = null;

    // <xs:any namespace="##other" processContents="lax" minOccurs="0" maxOccurs="unbounded"/>
    protected List<Element> bastards = null;
    
  public InfoCard(InfoCard that) {
        this.certChain = that.certChain;
        this.privateKey = that.privateKey;
        
        this.informationCardReference = that.informationCardReference; // required
        this.cardName = that.cardName;
        this.issuer = that.issuer;
        this.timeIssued = that.timeIssued;
        this.timeExpires = that.timeExpires;
        this.privacyPolicy = that.privacyPolicy;
        this.tokenServiceReferenceList = that.tokenServiceReferenceList;
        this.tokenList = that.tokenList;
        this.claimList = that.claimList;
        this.requireAppliesTo = that.requireAppliesTo; // optional 
        this.lang = that.lang;
        this.CardType = that.CardType;
        this.IssuerName = that.IssuerName;
        this.bastards = that.bastards;
        this.cardImages = new ArrayList<String[]>(that.cardImages.size());
        this.frontHtml = that.frontHtml;
        this.backHtml = that.backHtml;
        Collections.copy(this.cardImages, that.cardImages);
    }

    public InfoCard() {
        this.certChain = null;
    }

    public InfoCard(JSONObject json) throws ParsingException {
      this.lang = json.optString("lang");
      
      String CardId = json.optString("CardId", null);
      String CardVersion = json.optString("CardVersion", null);
      if (CardId != null && CardVersion != null) {
        informationCardReference = new InformationCardReference(CardId, Integer.valueOf(CardVersion).longValue());
      }
      this.cardName = json.optString("CardName", null);
      this.CardType = json.optString("CardType", null);
      this.IssuerName = json.optString("IssuerName", null);
      JSONArray cardImages = json.optJSONArray("CardImages");
      if (cardImages != null && cardImages.length() > 0) {
    	  this.cardImages = new ArrayList<String[]>(cardImages.length());
    	  for (int i=0; i<cardImages.length(); i++) {
    		  JSONObject ii;
			try {
				ii = cardImages.getJSONObject(i);
				String base64BinaryCardImage = ii.getString("base64BinaryCardImage");
				String mimeType = ii.getString("mimeType");
				String hint = ii.optString("hint");
				String imageInfo[] = new String[3];
				imageInfo[0] = base64BinaryCardImage;
				imageInfo[1] = mimeType;
				imageInfo[2] = hint;
				this.cardImages.add(imageInfo);
			} catch (JSONException e) {
				throw new ParsingException(e);
			}
    	  }
      }
      this.issuer = json.optString("Issuer", null);

      this.timeIssued = json.optString("TimeIssued", null);
      this.timeExpires = json.optString("TimeExpired", null);
      
      this.tokenServiceReferenceList = null;
      try {
        JSONArray ja = null;
        try {
          ja = json.getJSONArray("TokenServiceList");
        } catch (JSONException e) {}
        if (ja != null && ja.length() > 0) {
          this.tokenServiceReferenceList = new ArrayList<TokenServiceReference>();
          for (int index=0; index<ja.length(); index++) {
            JSONObject jo = ja.getJSONObject(index);
            TokenServiceReference tsr = new TokenServiceReference(jo);
            tokenServiceReferenceList.add(tsr);
          }
        }
      } catch (JSONException e) {
        throw new ParsingException(e);
      }
      
      tokenList = null;
      try {
        JSONArray ja = null;
        try {
          ja = json.getJSONArray("SupportedTokenTypeList");
        } catch (JSONException e) {}
        if (ja != null && ja.length() > 0) {
          List<SupportedToken> supportedTokenList = new ArrayList<SupportedToken>();
          for (int index=0; index<ja.length(); index++) {
            String tokenType = ja.getString(index);
            SupportedToken token = new SupportedToken(tokenType);
            supportedTokenList.add(token);
          }
          tokenList = new SupportedTokenList(supportedTokenList);
        }
      } catch (JSONException e) {
        throw new ParsingException(e);
      }
        
      claimList = null;
      try {
        JSONArray ja = null;
        try {
          ja = json.getJSONArray("SupportedClaimTypeList");
        } catch (JSONException e) {}
        if (ja != null && ja.length() > 0) {
          List<SupportedClaim> list = new ArrayList<SupportedClaim>();
          for (int index=0; index<ja.length(); index++) {
            JSONObject jo = ja.getJSONObject(index);
            SupportedClaim claim = new SupportedClaim(jo);
            list.add(claim);
          }
          claimList = new SupportedClaimTypeList(list);
        }
      } catch (JSONException e) {
        throw new ParsingException(e);
      }
      
      requireAppliesTo = null;
      if (json.has("RequireAppliesTo")) {
        requireAppliesTo = new RequireAppliesTo(json.optBoolean("RequireAppliesTo"));
      }

      privacyPolicy = null;
      if (json.has("PrivacyPolicyUri")) {
        try {
          privacyPolicy = new PrivacyNotice(
              json.getString("PrivacyPolicyUri"), Integer.valueOf(json.getString("PrivacyPolicyVersion")).longValue());
        } catch (URISyntaxException e) {
          throw new ParsingException(e);
        } catch (JSONException e) {
          throw new ParsingException(e);
        }
      }

      requireStrongRecipientIdentity = false;
      if (json.has("RequireStrongRecipientIdentity")) {
        try {
          requireStrongRecipientIdentity = json.getBoolean("RequireStrongRecipientIdentity");
        } catch (JSONException e) {
          throw new ParsingException(e);
        }
      }

      frontHtml = null;
      if (json.has("frontHtml")) {
        try {
        	frontHtml = json.getString("frontHtml");
        } catch (JSONException e) {
          throw new ParsingException(e);
        }
      }

      backHtml = null;
      if (json.has("backHtml")) {
        try {
        	backHtml = json.getString("backHtml");
        } catch (JSONException e) {
          throw new ParsingException(e);
        }
      }

      issuerInformation = null;
      if (json.has("IssuerInformation")) {
        try {
          JSONArray ja = json.getJSONArray("IssuerInformation");
          for (int index=0; index<ja.length(); index++) {
            JSONObject jo = ja.getJSONObject(index);
            // FIXME hier geht es weiter
          }
        } catch (JSONException e) {
          throw new ParsingException(e);
        }
      }
      
      try {
        if ((issuerInformation != null) && (issuerInformation.size() > 0)) {
          JSONArray ja = new JSONArray();
          int index = 0;
          for (String entryName : issuerInformation.keySet()) {
            String entryValue = issuerInformation.get(entryName);
            JSONObject jo = new JSONObject();
              jo.put("EntryName", entryName);
              jo.put("EntryValue", entryValue);
              ja.put(index++, jo);
          }
          json.put("IssuerInformation", ja);
        }
      } catch (JSONException e) {
        throw new ParsingException(e);
      }
      
      try {
        if (bastards != null) {
          JSONArray ja = new JSONArray();
          // <xs:any namespace="##other" processContents="lax" minOccurs="0" maxOccurs="unbounded"/>
          int index = 0;
          for (Element bastard : bastards) {
            JSONObject jo = XmlUtils.toJSON(bastard);
            ja.put(index++, jo);
          }
          if (index >0) { 
            json.put("ExtraElements", ja);
          }
        }
      } catch (JSONException e) {
        throw new ParsingException(e);
      }
  
    }

    public InfoCard(RoamingInformationCard ric) throws ParsingException {
      InformationCardMetaData metaData = ric.getInformationCardMetaData();
      
      // this.backgroudColor = metaData.getBackgroundColor(); // FIXME
      
      List<String[]> ci = metaData.getCardImages();
      this.cardImages = new ArrayList<String[]>(ci.size());
      Collections.copy(this.cardImages, ci);

      this.frontHtml = metaData.getFrontHtml();
      this.backHtml = metaData.getBackHtml();
      
      this.lang = metaData.getLang();
      this.requireStrongRecipientIdentity = metaData.getRequireStrongRecipientIdentity();
      
      this.certChain = null;
      this.privateKey = null;
      
      this.informationCardReference = new InformationCardReference(metaData.getCardId(), metaData.getCardVersion());
      
      cardName = metaData.getCardName();
      this.issuer = metaData.getIssuer();
      
      this.timeIssued = metaData.getTimeIssued();
      this.timeExpires = metaData.getTimeExpires();

      try {
        this.privacyPolicy = new PrivacyNotice(metaData.getPrivacyPolicy(), metaData.getPrivacyPolicyVersion());
      } catch (URISyntaxException e) {
        throw new ParsingException(e);
      }
      
      this.tokenServiceReferenceList = metaData.getTokenServiceReference();
      
      this.tokenList = metaData.getTokenList();
      this.claimList = metaData.getClaimList();
      
      this.requireAppliesTo = metaData.getRequireAppliesTo(); 

      this.CardType = metaData.getCardType();
      this.IssuerName = metaData.getIssuerName();
      
      this.issuerInformation = null; // FIXME unimplemented in RoamingInformationCard

      // <xs:any namespace="##other" processContents="lax" minOccurs="0" maxOccurs="unbounded"/>
      this.bastards = null; // // FIXME unimplemented in RoamingInformationCard

      if (metaData.getIsSelfIssued()) {
        SelfIssuedInformationCardPrivateData sicPrivateData = 
          (SelfIssuedInformationCardPrivateData)ric.getInformationCardPrivateData();
        SelfIssuedClaims selfIssuedClaims = sicPrivateData.getSelfIssuedClaims(); // FIXME unused 
        this.masterSecretBase64 = sicPrivateData.getMasterKey();
      } else {
        ManagedInformationCardPrivateData managedPrivateData = 
          (ManagedInformationCardPrivateData)ric.getInformationCardPrivateData();
        this.masterSecretBase64 = managedPrivateData.getMasterKey();
      }
    }

    public InfoCard(Element infoCardElement) throws ParsingException {
      // <ic:InformationCard xml:lang="xs:language" ...> 
      //  <ic:InformationCardReference> ... </ic:InformationCardReference> 
      //  <ic:CardName> xs:string </ic:CardName> ? 
      //  <ic:CardImage MimeType=�xs:string�> xs:base64Binary </ic:CardImage> ? 
      //  <ic:Issuer> xs:anyURI </ic:Issuer> 
      //  <ic:TimeIssued> xs:dateTime </ic:TimeIssued> 
      //  <ic:TimeExpires> xs:dateTime </ic:TimeExpires> ? 
      //  <ic:TokenServiceList> ... </ic:TokenServiceList> 
      //  <ic:SupportedTokenTypeList> ... </ic:SupportedTokenTypeList> 
      //  <ic:SupportedClaimTypeList> ... </ic:SupportedClaimTypeList> 
      //  <ic:RequireAppliesTo ...> ... </ic:RequireAppliesTo> ? 
      //  <ic:PrivacyNotice ...> ... </ic:PrivacyNotice> ? 
      //  ... 
      // </ic:InformationCard>
      String name = infoCardElement.getLocalName();
      if ("InformationCard".equals(name)) {
        createFromElement(infoCardElement);
      } else {
          throw new ParsingException("Expected InformationCard but found " + name);
      }
    }
    
    private List<Element> children(Elements kids) {
      if (kids == null) return null;
      if (kids.size() == 0) return new ArrayList<Element>();
      ArrayList<Element> children = new ArrayList<Element>(kids.size());
      for (int i=0; i<kids.size(); i++) {
        children.add(kids.get(i));
      }
      return children;
    }
    
    protected void createFromElement(Element infoCardElement)
      throws ParsingException {
      List<Element> children = children(infoCardElement.getChildElements());
      
    lang = infoCardElement.getAttributeValue("lang");
    Elements elts = infoCardElement.getChildElements("InformationCardReference", WSConstants.INFOCARD_NAMESPACE);
    if (elts.size() == 1) {
      Element elt = elts.get(0);
      children.remove(elt);
      informationCardReference = new InformationCardReference(elt);
    } else {
      throw new ParsingException("Found " + elts.size() + " elements of InformationCardReference");
    }
    elts = infoCardElement.getChildElements("CardName", WSConstants.INFOCARD_NAMESPACE);
    if (elts.size() == 1) {
      Element elt = elts.get(0);
      children.remove(elt);
      cardName = elt.getValue();
    } else {
      if (elts.size() > 1) {
        throw new ParsingException("Found " + elts.size() + " elements of CardName");
      }
    }
    elts = infoCardElement.getChildElements("CardType", WSConstants.INFOCARD09_NAMESPACE);
    if (elts.size() == 1) {
      Element elt = elts.get(0);
      children.remove(elt);
      CardType = elt.getValue();
    } else {
      if (elts.size() > 1) {
        throw new ParsingException("Found " + elts.size() + " elements of CardType");
      }
    }
    elts = infoCardElement.getChildElements("IssuerName", WSConstants.INFOCARD09_NAMESPACE);
    if (elts.size() == 1) {
      Element elt = elts.get(0);
      children.remove(elt);
      IssuerName = elt.getValue();
    } else {
      if (elts.size() > 1) {
        throw new ParsingException("Found " + elts.size() + " elements of IssuerName");
      }
    }
    elts = infoCardElement.getChildElements("CardImage", WSConstants.INFOCARD_NAMESPACE);
    for (int i=0; i<elts.size(); i++) {
      Element elt = elts.get(i);
      children.remove(elt);
      String base64BinaryCardImage = elt.getValue();
      String mimeType = elt.getAttributeValue("MimeType");
      String hint = elt.getAttributeValue("hint"); // openinfocard extension
	  String imageInfo[] = new String[3];
	  imageInfo[0] = base64BinaryCardImage;
	  imageInfo[1] = mimeType;
	  imageInfo[2] = hint;
      if (cardImages == null) {
    	  cardImages = new ArrayList<String[]>();
      }
	  cardImages.add(imageInfo);
    }

    elts = infoCardElement.getChildElements("Issuer", WSConstants.INFOCARD_NAMESPACE);
    if (elts.size() == 1) {
      Element elt = elts.get(0);
      children.remove(elt);
      issuer = elt.getValue();
    } else {
      throw new ParsingException("Found " + elts.size() + " elements of Issuer");
    }
    elts = infoCardElement.getChildElements("TimeIssued", WSConstants.INFOCARD_NAMESPACE);
    if (elts.size() == 1) {
      Element elt = elts.get(0);
      children.remove(elt);
      timeIssued = elt.getValue();
    } else {
      throw new ParsingException("Found " + elts.size() + " elements of TimeIssued");
    }
    elts = infoCardElement.getChildElements("TimeExpires", WSConstants.INFOCARD_NAMESPACE);
    if (elts.size() == 1) {
      Element elt = elts.get(0);
      children.remove(elt);
      timeIssued = elt.getValue();
    } else {
      if (elts.size() > 1) {
        throw new ParsingException("Found " + elts.size() + " elements of TimeExpires");
      }
    }
    boolean isSelfIssued = org.xmldap.infocard.Constants.ISSUER_XMLSOAP.equals(issuer);
    if (!isSelfIssued) {
      elts = infoCardElement.getChildElements("TokenServiceList", WSConstants.INFOCARD_NAMESPACE);
      if (elts.size() == 1) {
        Element elt = elts.get(0);
        children.remove(elt);
        Elements tokenServiceList = elt.getChildElements("TokenService", WSConstants.INFOCARD_NAMESPACE);
        if (tokenServiceList.size() < 1) {
          throw new ParsingException("missing TokenService children in TokenServiceList");
        } else {
          for (int i=0; i<tokenServiceList.size(); i++) {
            Element tokenServiceElement = tokenServiceList.get(i);
            TokenServiceReference tsr = new TokenServiceReference(tokenServiceElement);
            if (tokenServiceReferenceList == null) {
              tokenServiceReferenceList = new ArrayList<TokenServiceReference>();
            }
            tokenServiceReferenceList.add(tsr);
          }
        }
      } else {
        throw new ParsingException("Found " + elts.size() + " elements of TokenServiceList");
      }
    }
    elts = infoCardElement.getChildElements("SupportedTokenTypeList", WSConstants.INFOCARD_NAMESPACE);
    if (elts.size() == 1) {
      Element elt = elts.get(0);
      children.remove(elt);
      tokenList = new SupportedTokenList(elt);
    } else {
      throw new ParsingException("Found " + elts.size() + " elements of SupportedTokenTypeList");
    }

//          <ic:SupportedClaimTypeList> 
//           (<ic:SupportedClaimType Uri=�xs:anyURI�> 
//             <ic:DisplayTag> xs:string </ic:DisplayTag> ? 
//             <ic:Description> xs:string </ic:Description> ? 
//            </ic:SupportedClaimType>) + 
//            </ic:SupportedClaimTypeList>
    elts = infoCardElement.getChildElements("SupportedClaimTypeList", WSConstants.INFOCARD_NAMESPACE);
    if (elts.size() == 1) {
      Element elt = elts.get(0);
      children.remove(elt);
      claimList = new SupportedClaimTypeList(elt);
    } else {
      throw new ParsingException("Found " + elts.size() + " elements of SupportedClaimTypeList in\n" + infoCardElement.toXML());
    }
    elts = infoCardElement.getChildElements("RequireAppliesTo", WSConstants.INFOCARD_NAMESPACE);
    if (elts.size() == 1) {
      Element elt = elts.get(0);
      children.remove(elt);
      requireAppliesTo = new RequireAppliesTo(elt);
    } else {
      if (elts.size() > 1) {
        throw new ParsingException("Found " + elts.size() + " elements of RequireAppliesTo");
      }
    }
    elts = infoCardElement.getChildElements("PrivacyNotice", WSConstants.INFOCARD_NAMESPACE);
    if (elts.size() == 1) {
      Element elt = elts.get(0);
      children.remove(elt);
      privacyPolicy = new PrivacyNotice(elt);
    } else {
      if (elts.size() > 1) {
        throw new ParsingException("Found " + elts.size() + " elements of PrivacyNotice");
      }
    }
    elts = infoCardElement.getChildElements("RequireStrongRecipientIdentity", WSConstants.INFOCARD07_NAMESPACE);
    if (elts.size() == 1) {
      Element elt = elts.get(0);
      children.remove(elt);
      requireStrongRecipientIdentity = true;
    } else {
      if (elts.size() ==0) {
        requireStrongRecipientIdentity = false;
      } else {
        if (elts.size() > 1) {
          throw new ParsingException("Found " + elts.size() + " elements of RequireStrongRecipientIdentity");
        }
      }
    }
    elts = infoCardElement.getChildElements("FrontHtml", WSConstants.INFOCARD11_NAMESPACE);
    if (elts.size() == 1) {
      Element elt = elts.get(0);
      children.remove(elt);
      frontHtml = elt.getValue();
    } else {
      if (elts.size() ==0) {
    	  frontHtml = null;
      } else {
        if (elts.size() > 1) {
          throw new ParsingException("Found " + elts.size() + " elements of FrontHtml");
        }
      }
    }
    elts = infoCardElement.getChildElements("BackHtml", WSConstants.INFOCARD11_NAMESPACE);
    if (elts.size() == 1) {
      Element elt = elts.get(0);
      children.remove(elt);
      backHtml = elt.getValue();
    } else {
      if (elts.size() ==0) {
    	  backHtml = null;
      } else {
        if (elts.size() > 1) {
          throw new ParsingException("Found " + elts.size() + " elements of BackHtml");
        }
      }
    }
    elts = infoCardElement.getChildElements("IssuerInformation", WSConstants.INFOCARD07_NAMESPACE);
    if (elts.size() == 1) {
      Element elt = elts.get(0);
      children.remove(elt);
      issuerInformation = new HashMap<String, String>();
      elts = elt.getChildElements("IssuerInformationEntry", WSConstants.INFOCARD07_NAMESPACE);
      if (elts.size() > 1) {
        Element issuerInformationEntry = elts.get(0);
        String name = null;
        elts = issuerInformationEntry.getChildElements("EntryName", WSConstants.INFOCARD07_NAMESPACE);
        if (elts.size() == 1) {
          elt = elts.get(0);
          name = elt.getValue();
          if ((name == null) || ("".equals(name))) {
            throw new ParsingException("EntryName is null or empty");
          }
        } else {
          throw new ParsingException("Found " + elts.size() + " elements of EntryName; expected exactly one.");
        }
        String value = null;
        elts = issuerInformationEntry.getChildElements("EntryValue", WSConstants.INFOCARD07_NAMESPACE);
        if (elts.size() == 1) {
          elt = elts.get(0);
          value = elt.getValue();
          if (value == null) {
            throw new ParsingException("EntryValue is null");
          }
        } else {
          throw new ParsingException("Found " + elts.size() + " elements of EntryValue; expected exactly one.");
        }
        issuerInformation.put(name, value);
      } else {
        throw new ParsingException("Expected IssuerInformationEntry");
      }
    } else {
      if (elts.size() > 1) {
        throw new ParsingException("Found " + elts.size() + " elements of IssuerInformation");
      }
    }

    bastards = children; 
  }

//    public InfoCard(X509Certificate cert, PrivateKey privateKey) {
//        this.certChain = new X509Certificate[]{cert};
//        this.privateKey = privateKey;
//    }

    public InfoCard(X509Certificate[] certChain, PrivateKey privateKey) {
      if (certChain == null) {
        throw new IllegalArgumentException("InfoCard: certCain == null");
      }
      if (certChain.length == 0) {
        throw new IllegalArgumentException("InfoCard: certCain.size() == 0");
      }
        this.certChain = certChain;
        this.privateKey = privateKey;
    }

    public void setRequireAppliesTo(boolean optional) {
        this.requireAppliesTo = new RequireAppliesTo(optional);
    }

//    public boolean signCard() {
//        return signCard;
//    }
//
//    public void setSignCard(boolean signCard) {
//        this.signCard = signCard;
//    }

    public String getIssuer() {
        return issuer;
    }

  public void setLang(String lang) {
    this.lang = lang;
  }

    public String getLang() {
        return lang;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getPrivacyPolicy() {
        return privacyPolicy.getUri();
    }

    public long getPrivacyPolicyVersion() {
        return privacyPolicy.getVersion();
    }

    public void setPrivacyPolicy(String privacyPolicy, long version) throws URISyntaxException {
        this.privacyPolicy = new PrivacyNotice(privacyPolicy, version);
    }

    public String getCardType() { return CardType; }
    public void setCardType(String cardType) {
      CardType = cardType;
    }
    
    public String getIssuerName() { return IssuerName; }
    public void setIssuerName(String issuerName) {
      IssuerName = issuerName;
    }
    
    public String getCardName() {
        return cardName;
    }

    public void setCardName(String cardName) {
        this.cardName = cardName;
    }

    public String getCardId() {
        return informationCardReference.getCardId();
    }

    public void setCardId(String cardId, long cardVersion) {
        this.informationCardReference = new InformationCardReference(cardId, cardVersion);
    }

    public long getCardVersion() {
        return informationCardReference.getCardVersion();
    }

    public String getFrontHtml() {
		return frontHtml;
	}

	public void setFrontHtml(String frontHtml) {
		this.frontHtml = frontHtml;
	}

	public String getBackHtml() {
		return backHtml;
	}

	public void setBackHtml(String backHtml) {
		this.backHtml = backHtml;
	}

	public List<String[]> getCardImages() {
    	return cardImages;
    }

    public String getBase64BinaryCardImage() {
    	if (cardImages != null) {
    		if (cardImages.size() == 1) {
    			return cardImages.get(0)[0];
    		} else {
    			if (cardImages.size() == 0) { return null; }
    			for (int i=0; i<cardImages.size(); i++) {
    				String hint = cardImages.get(i)[2];
    				if (hint != null && "front".equals(hint)) {
    					return cardImages.get(i)[0];
    				}
    			}
    			return cardImages.get(0)[0];
    		}
    	}
    	return null;
  }

  public String getMimeType() {
  	if (cardImages != null) {
		if (cardImages.size() == 1) {
			return cardImages.get(0)[1];
		} else {
			if (cardImages.size() == 0) { return null; }
			for (int i=0; i<cardImages.size(); i++) {
				String hint = cardImages.get(i)[2];
				if (hint != null && "front".equals(hint)) {
					return cardImages.get(i)[1];
				}
			}
			return cardImages.get(0)[1];
		}
	}
	return null;
  }

    public void setBase64BinaryCardImage(String base64BinaryCardImage, String mimeType) {
    	setBase64BinaryCardImage(base64BinaryCardImage, mimeType, null);
    }

    public void setBase64BinaryCardImage(String base64BinaryCardImage, String mimeType, String hint) {
    	if (cardImages == null) {
    		cardImages = new ArrayList<String[]>();
    	}
		String imageInfo[] = new String[3];
		imageInfo[0] = base64BinaryCardImage;
		imageInfo[1] = mimeType;
		imageInfo[2] = hint;

		cardImages.add(imageInfo);
    }

    public String getTimeIssued() {
        return timeIssued;
    }

    public void setTimeIssued(String timeIssued) {
      Calendar dt = XSDDateTime.parse(timeIssued); 
        this.timeIssued = XSDDateTime.getDateTime(dt);
    }

    public String getTimeExpires() {
        return timeExpires;
    }

    public void setTimeExpires(String timeExpires) {
      if (timeExpires != null) {
        Calendar dt = XSDDateTime.parse(timeExpires); 
          this.timeExpires = XSDDateTime.getDateTime(dt);
      } else {
        this.timeExpires = null;
      }
    }

    public List<TokenServiceReference> getTokenServiceReference() {
        return tokenServiceReferenceList;
    }

    public void setTokenServiceReference(List<TokenServiceReference> tokenServiceReference) {
        this.tokenServiceReferenceList = tokenServiceReference;
    }

    public SupportedTokenList getTokenList() {
        return tokenList;
    }

    public void setTokenList(SupportedTokenList tokenList) {
        this.tokenList = tokenList;
    }

    public SupportedClaimTypeList getClaimList() {
        return claimList;
    }

    public void setClaimList(SupportedClaimTypeList claimList) {
        this.claimList = claimList;
    }

    public Element serialize() throws SerializationException {

        Element infoCard = new Element(WSConstants.INFOCARD_PREFIX + ":InformationCard", WSConstants.INFOCARD_NAMESPACE);
        if (lang != null) {
          Attribute langA = new Attribute("xml:lang", "http://www.w3.org/XML/1998/namespace", lang);
          infoCard.addAttribute(langA);
        } else {
          Attribute lang = new Attribute("xml:lang", "http://www.w3.org/XML/1998/namespace", "en-us");
          infoCard.addAttribute(lang);
        }
      appendChildren(infoCard);
        
        if (certChain != null && certChain.length > 0) {
            System.out.println("SigningCArd");
            //Get the signing util
            String signingAlgorithm = "SHA1withRSA"; // FIXME remove hardcoding of algorithm
            InfoCardSignature signer = new InfoCardSignature(certChain,privateKey, signingAlgorithm);

            Element signedCard = null;

            try {

                signedCard = signer.sign(infoCard);
            } catch (SigningException e) {
                throw new SerializationException(e);
            }

            return signedCard;

        }
        return infoCard;

    }

  protected void appendChildren(Element infoCard) throws SerializationException {
    infoCard.addNamespaceDeclaration(WSConstants.MEX_PREFIX,WSConstants.MEX_04_09);
        infoCard.addNamespaceDeclaration(WSConstants.DSIG_PREFIX,WSConstants.DSIG_NAMESPACE);
        infoCard.addNamespaceDeclaration(WSConstants.INFOCARD_PREFIX, WSConstants.INFOCARD_NAMESPACE);
        infoCard.addNamespaceDeclaration(WSConstants.WSA_PREFIX,WSConstants.WSA_NAMESPACE_05_08);
        infoCard.addNamespaceDeclaration(WSConstants.WSA_ID_PREFIX,WSConstants.WSA_ID_06_02);
        infoCard.addNamespaceDeclaration(WSConstants.TRUST_PREFIX,WSConstants.TRUST_NAMESPACE_05_02);

        if (informationCardReference != null) {
          Element infoCardReference = new Element(WSConstants.INFOCARD_PREFIX + ":InformationCardReference", WSConstants.INFOCARD_NAMESPACE);
          Element cardIdElm = new Element(WSConstants.INFOCARD_PREFIX + ":CardId", WSConstants.INFOCARD_NAMESPACE);
          cardIdElm.appendChild(informationCardReference.getCardId());
          infoCardReference.appendChild(cardIdElm);
          Element cardVersionElm = new Element(WSConstants.INFOCARD_PREFIX + ":CardVersion", WSConstants.INFOCARD_NAMESPACE);
          cardVersionElm.appendChild(String.valueOf(informationCardReference.getCardVersion()));
          infoCardReference.appendChild(cardVersionElm);
          infoCard.appendChild(infoCardReference);
        } else {
          throw new SerializationException("InformationCardReference is required");
        }
        if (cardName != null) { // optional
          Element cardNameElm = new Element(WSConstants.INFOCARD_PREFIX + ":CardName", WSConstants.INFOCARD_NAMESPACE);
          cardNameElm.appendChild(cardName);
          infoCard.appendChild(cardNameElm);
        }
        if (CardType != null) { // optional
          Element cardNameElm = new Element(WSConstants.INFOCARD09_PREFIX + ":CardType", WSConstants.INFOCARD09_NAMESPACE);
          cardNameElm.appendChild(CardType);
          infoCard.appendChild(cardNameElm);
        }
        if (IssuerName != null) { // optional
            Element cardNameElm = new Element(WSConstants.INFOCARD09_PREFIX + ":IssuerName", WSConstants.INFOCARD09_NAMESPACE);
            cardNameElm.appendChild(IssuerName);
            infoCard.appendChild(cardNameElm);
        }
        if (frontHtml != null) { // optional
            Element elt = new Element(WSConstants.INFOCARD11_PREFIX + ":FrontHtml", WSConstants.INFOCARD11_NAMESPACE);
            elt.appendChild(frontHtml);
            infoCard.appendChild(elt);
        }
        if (backHtml != null) { // optional
            Element elt = new Element(WSConstants.INFOCARD11_PREFIX + ":BackHtml", WSConstants.INFOCARD11_NAMESPACE);
            elt.appendChild(backHtml);
            infoCard.appendChild(elt);
        }

        if (cardImages != null) {
        	for (int i=0; i<cardImages.size(); i++) {
        		String imageInfo[] = cardImages.get(i);
        		String base64BinaryCardImage = imageInfo[0];
        		String mimeType = imageInfo[1];
        		String hint = imageInfo[2];
	            Element cardImageElm = new Element(WSConstants.INFOCARD_PREFIX + ":CardImage", WSConstants.INFOCARD_NAMESPACE);
	            cardImageElm.appendChild(base64BinaryCardImage);
	            Attribute mime = new Attribute("MimeType", mimeType);
	            cardImageElm.addAttribute(mime);
	            if (hint != null && !"".equals(hint)) {
		            Attribute hintAttr = new Attribute("hint", hint);
		            cardImageElm.addAttribute(hintAttr);
	            }
	            infoCard.appendChild(cardImageElm);
        	}
        }

        if (issuer != null) {
          Element issuerElm = new Element(WSConstants.INFOCARD_PREFIX + ":Issuer", WSConstants.INFOCARD_NAMESPACE);
          issuerElm.appendChild(issuer);
          infoCard.appendChild(issuerElm);
        } else {
          throw new SerializationException("issuer is null but required");
        }
        //Element issuerNameElm = new Element(WSConstants.INFOCARD_PREFIX + ":IssuerName", WSConstants.INFOCARD_NAMESPACE);
        //issuerNameElm.appendChild(issuerName);
        //TODO - Remove this for RC1
        //infoCard.appendChild(issuerNameElm);

        if (timeIssued != null) {
          Element timeIssuedElm = new Element(WSConstants.INFOCARD_PREFIX + ":TimeIssued", WSConstants.INFOCARD_NAMESPACE);
          timeIssuedElm.appendChild(timeIssued);
          System.out.println("TimeIssued=" + timeIssued);
          //timeIssuedElm.appendChild("2006-09-04T19:39:19.6053152Z");
          infoCard.appendChild(timeIssuedElm);
        } else {
          throw new SerializationException("timeIssued is null but required");
        }
        if (timeExpires != null) {
          Element timeExpiresElm = new Element(WSConstants.INFOCARD_PREFIX + ":TimeExpires", WSConstants.INFOCARD_NAMESPACE);
          timeExpiresElm.appendChild(timeExpires);
          System.out.println("TimeExpires=" + timeExpires);
          infoCard.appendChild(timeExpiresElm);
        } // else optional
        
        if ((tokenServiceReferenceList != null) && (tokenServiceReferenceList.size() > 0)){
            Element tokenServiceList = new Element(WSConstants.INFOCARD_PREFIX + ":TokenServiceList", WSConstants.INFOCARD_NAMESPACE);
            for (int i=0; i<tokenServiceReferenceList.size(); i++) {
              TokenServiceReference tsr = tokenServiceReferenceList.get(i);
              Element tokenServiceElement = tsr.serialize();
              tokenServiceList.appendChild(tokenServiceElement);
            }
          infoCard.appendChild(tokenServiceList);
        } // else optional 
        if (tokenList != null) {
          infoCard.appendChild(tokenList.serialize());
        } else {
          throw new SerializationException("SupportedTokenList is null but required");
        }
        
        if (claimList != null) {
          infoCard.appendChild(claimList.serialize());
        } else {
          throw new SerializationException("SupportedClaimTypeList is null but required");
        }
        
        if (requireAppliesTo != null) {
            Element requireAppliesToElm = new Element(WSConstants.INFOCARD_PREFIX + ":RequireAppliesTo", WSConstants.INFOCARD_NAMESPACE);
            Attribute required = (requireAppliesTo.getOptional()) ? new Attribute("Optional", "true") : new Attribute("Optional", "false");
            requireAppliesToElm.addAttribute(required);
            infoCard.appendChild(requireAppliesToElm);
        }

        if (privacyPolicy != null) {
          Element ppElm = new Element(WSConstants.INFOCARD_PREFIX + ":PrivacyNotice", WSConstants.INFOCARD_NAMESPACE);
          Attribute version = new Attribute("Version", String.valueOf(privacyPolicy.getVersion()));
          ppElm.addAttribute(version);
          ppElm.appendChild(privacyPolicy.getUri());
          infoCard.appendChild(ppElm);
        } // else optional

        if (requireStrongRecipientIdentity == true) {
            Element elm = new Element(WSConstants.INFOCARD07_PREFIX + ":RequireStrongRecipientIdentity", WSConstants.INFOCARD07_NAMESPACE);
            infoCard.appendChild(elm);
        }

        if ((issuerInformation != null) && (issuerInformation.size() > 0)) {
        Element issuerInformationElm = new Element(WSConstants.INFOCARD07_PREFIX + ":IssuerInformation", WSConstants.INFOCARD07_NAMESPACE);
          for (String entryName : issuerInformation.keySet()) {
            String entryValue = issuerInformation.get(entryName);
            Element issuerInformationEntryElm = new Element(WSConstants.INFOCARD07_PREFIX + ":IssuerInformationEntry", WSConstants.INFOCARD07_NAMESPACE);
            Element entryNameElm = new Element(WSConstants.INFOCARD07_PREFIX + ":EntryName", WSConstants.INFOCARD07_NAMESPACE);
            entryNameElm.appendChild(entryName);
            Element entryValueElm = new Element(WSConstants.INFOCARD07_PREFIX + ":EntryValue", WSConstants.INFOCARD07_NAMESPACE);
            entryValueElm.appendChild(entryValue);
            issuerInformationEntryElm.appendChild(entryNameElm);
            issuerInformationEntryElm.appendChild(entryValueElm);
            issuerInformationElm.appendChild(issuerInformationEntryElm);
          }
          infoCard.appendChild(issuerInformationElm);
        }
        
        if (bastards != null) {
          // <xs:any namespace="##other" processContents="lax" minOccurs="0" maxOccurs="unbounded"/>
          for (Element bastard : bastards) {
            Element node = (Element)bastard.copy();
            node.detach();
            infoCard.appendChild(node);
          }
        }
  }

  private void appendChildren(JSONObject json) throws SerializationException {
    try {
        if (informationCardReference != null) {
          json.put("CardId", informationCardReference.getCardId());
          json.put("CardVersion", informationCardReference.getCardVersion());
        } else {
          throw new SerializationException("InformationCardReference is required");
        }
        if (cardName != null) { // optional
          json.put("CardName", cardName);
        }
        if (CardType != null) { // optional
          json.put("CardType", CardType);
        }
        if (IssuerName != null) { // optional
          json.put("IssuerName", IssuerName);
        }

        if (cardImages != null) {
        	JSONArray ja = new JSONArray();
        	for (int i=0; i<cardImages.size(); i++) {
        		JSONObject jo = new JSONObject();
        		String[] imageInfo = cardImages.get(i);
        		jo.put("base64BinaryCardImage", imageInfo[0]);
        		jo.put("mimeType", imageInfo[1]);
        		if (imageInfo[2] != null) {
        			jo.put("hint", imageInfo[2]);
        		}
        		ja.put(i, jo);
        	}
        	json.put("CardImages", ja);
        }

        if (issuer != null) {
          json.put("Issuer", issuer);
        } else {
          throw new SerializationException("issuer is null but required");
        }
        //Element issuerNameElm = new Element(WSConstants.INFOCARD_PREFIX + ":IssuerName", WSConstants.INFOCARD_NAMESPACE);
        //issuerNameElm.appendChild(issuerName);
        //TODO - Remove this for RC1
        //infoCard.appendChild(issuerNameElm);

        if (timeIssued != null) {
          json.put("TimeIssued", timeIssued);
        } else {
          throw new SerializationException("timeIssued is null but required");
        }
        if (timeExpires != null) {
          json.put("TimeExpired", timeExpires);
        } // else optional
        
        if ((tokenServiceReferenceList != null) && (tokenServiceReferenceList.size() > 0)){
          JSONArray ja = new JSONArray();
            for (int i=0; i<tokenServiceReferenceList.size(); i++) {
              TokenServiceReference tsr = tokenServiceReferenceList.get(i);
              JSONObject jo = tsr.toJSON();
              ja.put(i, jo);
            }
            json.put("TokenServiceList", ja);
        } // else optional 
        if (tokenList != null) {
          JSONArray ja = new JSONArray();
          Iterator<SupportedToken> tokens = tokenList.getSupportedTokens().iterator();
          int index = 0;
          while (tokens.hasNext()) {
              SupportedToken token = (SupportedToken) tokens.next();
              ja.put(index, token.getTokenType());
          }
          json.put("SupportedTokenTypeList", ja);
        } else {
          throw new SerializationException("SupportedTokenList is null but required");
        }
        
        if (claimList != null) {
          JSONArray ja = new JSONArray();
          Iterator<SupportedClaim> tokens = claimList.getSupportedClaims().iterator();
          int index = 0;
          while (tokens.hasNext()) {
            SupportedClaim token = (SupportedClaim) tokens.next();
            ja.put(index++, token.toJSON());
          }
          json.put("SupportedClaimTypeList", ja);
         } else {
          throw new SerializationException("SupportedClaimTypeList is null but required");
        }
        
        if (requireAppliesTo != null) {
          json.put("RequireAppliesTo", requireAppliesTo.getOptional());
        }

        if (privacyPolicy != null) {
          json.put("PrivacyPolicyVersion", privacyPolicy.getVersion());
          json.put("PrivacyPolicyUri", privacyPolicy.getUri());
        } // else optional

        if (requireStrongRecipientIdentity == true) {
          json.put("RequireStrongRecipientIdentity", true);
        }

        if ((issuerInformation != null) && (issuerInformation.size() > 0)) {
          JSONArray ja = new JSONArray();
          int index = 0;
          for (String entryName : issuerInformation.keySet()) {
            String entryValue = issuerInformation.get(entryName);
            JSONObject jo = new JSONObject();
            jo.put("EntryName", entryName);
            jo.put("EntryValue", entryValue);
            ja.put(index++, jo);
          }
          json.put("IssuerInformation", ja);
        }
        
        if (bastards != null) {
          JSONArray ja = new JSONArray();
          // <xs:any namespace="##other" processContents="lax" minOccurs="0" maxOccurs="unbounded"/>
          int index = 0;
          for (Element bastard : bastards) {
            JSONObject jo = XmlUtils.toJSON(bastard);
            ja.put(index++, jo);
          }
          if (index >0) { 
            json.put("ExtraElements", ja);
          }
        }
    } catch (JSONException e) {
      throw new SerializationException(e);
    }
    }
  
  private JSONObject sign(JSONObject json, String signingAlgorithm) {
    return null;
  }
  
  public JSONObject toJSON() throws SerializationException {
    try {
      JSONObject json = new JSONObject();
      
      if (lang != null) {
        json.put("lang", lang);
      }
      appendChildren(json);
        
      if (certChain != null && certChain.length > 0) {
        System.out.println("Signing JSON Card");
        //Get the signing util
        String signingAlgorithm = "SHA1withRSA";
      
        JSONObject signedJSON = sign(json, signingAlgorithm);
        return signedJSON;
    
      }
      
      return json;
    } catch (JSONException e) {
      throw new SerializationException(e);
    }
  }
  
    public String toXML() throws SerializationException {

        Element card = serialize();
        return card.toXML();

    }
    
  public RequireAppliesTo getRequireAppliesTo() {
    return requireAppliesTo;
  }


  public void setRequireAppliesTo() {
    this.requireAppliesTo = new RequireAppliesTo(false); // optional = false
  }


  public boolean getRequireStrongRecipientIdentity() {
    return requireStrongRecipientIdentity;
  }


  public void setRequireStrongRecipientIdentity(
      boolean requireStrongRecipientIdentity) {
    this.requireStrongRecipientIdentity = requireStrongRecipientIdentity;
  }

  public Map<String, String> getIssuerInformation() {
    return issuerInformation;
  }

  public void setIssuerInformation(Map<String, String> issuerInformation) {
    this.issuerInformation = issuerInformation;
  }

    public List<Element> getBastards() {
    return bastards;
  }

  public void setBastards(List<Element> bastards) {
    this.bastards = bastards;
  }

  public boolean checkValidity(String when) {
    Calendar whenCal;
    if (when != null) {
      whenCal = XSDDateTime.parse(when);
    } else {
      whenCal = XSDDateTime.parse(new XSDDateTime().getDateTime());
    }
    {
      Calendar timeIssued = XSDDateTime.parse(this.timeIssued);
      if (timeIssued.after(whenCal)) {
        // issued after when
        System.out.println("InfoCard: issued after when: " + this.timeIssued + " after " + XSDDateTime.getDateTime(whenCal));
        return false;
      }
    }
    if (this.timeExpires != null) {
      Calendar timeExpired = XSDDateTime.parse(this.timeExpires);
      if (timeExpired.before(whenCal)) {
        // expired before when
        System.out.println("InfoCard: expired before when: " + this.timeExpires + " before " + XSDDateTime.getDateTime(whenCal));
        return false;
      }
    }
    if (tokenServiceReferenceList == null) return false; 
    if (tokenServiceReferenceList.size() < 1) return false; 
    for (int index=0; index < tokenServiceReferenceList.size(); index++) {
      TokenServiceReference tsr = tokenServiceReferenceList.get(index);
      X509Certificate cert = tsr.getCert();
      if (cert != null) {
        Date date = whenCal.getTime();
        try {
          cert.checkValidity(date);
        } catch (CertificateExpiredException e) {
          System.out.println("InfoCard: " + e.getMessage());
          return false;
        } catch (CertificateNotYetValidException e) {
          System.out.println("InfoCard: " + e.getMessage());
          return false;
        }
      }
    }
    return false;
  }

  @Override
  public int compareTo(InfoCard obj) {
    if (this == obj) return 0;
    
    int comparison = issuer.compareTo(obj.issuer);
      if (comparison != 0) return comparison;
      
    comparison = informationCardReference.compareTo(obj.informationCardReference);
      if (comparison != 0) return comparison;
      
      // FIXME: implement the rest below although there is probably something wrong
      // with the issuer if the rest is not equal
//      private X509Certificate[] certChain = null;
//      private PrivateKey privateKey = null;
//      
//      private String cardName = null;
////      private String cardId = null; // required
////      private int cardVersion = 1; // required
//      private String base64BinaryCardImage;
//      String mimeType = null;
//      //private String issuerName = null;
//      private String timeIssued = null;
//      private String timeExpires = null;
//      private PrivacyNotice privacyPolicy = null;
//      private List<TokenServiceReference> tokenServiceReferenceList = null;
//      private SupportedTokenList tokenList = null;
//      private SupportedClaimTypeList claimList = null;
//      private String userName = null;
//      private RequireAppliesTo requireAppliesTo = null; // optional 
//      protected String lang = null;
//
//      boolean requireStrongRecipientIdentity = true;
//
//      Map<String, String> issuerInformation = null;
//
//      // <xs:any namespace="##other" processContents="lax" minOccurs="0" maxOccurs="unbounded"/>
//      protected List<Element> bastards = null;
      
    return 0;
  }
}
