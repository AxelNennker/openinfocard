package org.xmldap.firefox;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

import nu.xom.Attribute;
import nu.xom.Element;

import org.xmldap.exceptions.SerializationException;
import org.xmldap.exceptions.SigningException;
import org.xmldap.util.RandomGUID;
import org.xmldap.util.XSDDateTime;
import org.xmldap.ws.WSConstants;
import org.xmldap.xml.Serializable;
import org.xmldap.xmldsig.AsymmetricKeyInfo;
import org.xmldap.xmldsig.BaseEnvelopedSignature;
import org.xmldap.xmldsig.Reference;
import org.xmldap.xmldsig.SAMLTokenKeyInfo;
import org.xmldap.xmldsig.Signature;

public class RequestSecurityToken implements Serializable{
	Element soapEnvelope = null;
	
	public RequestSecurityToken(
			String sts, Element encryptedSamlAssertion,
			AsymmetricKeyInfo keyInfo, PrivateKey privateKey, 
			SAMLTokenKeyInfo samlTokenKeyInfo) throws SigningException, SerializationException {
        soapEnvelope = new Element(WSConstants.SOAP_PREFIX + ":Envelope", WSConstants.SOAP11_NAMESPACE);
        Element soapHeader = new Element(WSConstants.SOAP_PREFIX + ":Header", WSConstants.SOAP11_NAMESPACE);
        List<Reference> references = new ArrayList<Reference>();
        {
        	{
//	        	<wsa:Action wsu:Id="_1">
//	        	http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue
//	        	</wsa:Action>
	        	Element wsa = new Element(WSConstants.WSA_PREFIX + ":Action", WSConstants.WSA_NAMESPACE_05_08);
	        	Attribute wsuId = new Attribute(WSConstants.WSU_PREFIX + ":Id", WSConstants.WSU_NAMESPACE, "_1");
	        	wsa.addAttribute(wsuId);
	        	wsa.appendChild("http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue");
	        	soapHeader.appendChild(wsa);
	        	references.add(new Reference(wsa, wsuId.getValue(), null, "SHA"));
        	}
        	{
//        		<wsa:MessageID wsu:Id="_2">
//        		urn:uuid:eb9e1c77-0cea-4f2f-a586-78c15536137c
//        		</wsa:MessageID>
        		Element wsa = new Element(WSConstants.WSA_PREFIX + ":MessageID", WSConstants.WSA_NAMESPACE_05_08);
	        	Attribute wsuId = new Attribute(WSConstants.WSU_PREFIX + ":Id", WSConstants.WSU_NAMESPACE, "_2");
	        	wsa.addAttribute(wsuId);
	        	RandomGUID guid = new RandomGUID();
	        	wsa.appendChild("urn:" + guid);
	        	soapHeader.appendChild(wsa);
	        	references.add(new Reference(wsa, wsuId.getValue(), null, "SHA"));
        	}
        	{
//        		<wsa:To wsu:Id="_3">http://contoso.com/sts</wsa:To>
        		Element wsa = new Element(WSConstants.WSA_PREFIX + ":To", WSConstants.WSA_NAMESPACE_05_08);
	        	Attribute wsuId = new Attribute(WSConstants.WSU_PREFIX + ":Id", WSConstants.WSU_NAMESPACE, "_3");
	        	wsa.addAttribute(wsuId);
	        	wsa.appendChild(sts);
	        	soapHeader.appendChild(wsa);
	        	references.add(new Reference(wsa, wsuId.getValue(), null, "SHA"));
        	}
        	{
//        		<wsa:ReplyTo wsu:Id="_4">
//        		<wsa:Address>
//        		http://www.w3.org/2005/08/addressing/anonymous
//        		</wsa:Address>
//        		</wsa:ReplyTo>
        		Element wsa = new Element(WSConstants.WSA_PREFIX + ":ReplyTo", WSConstants.WSA_NAMESPACE_05_08);
	        	Attribute wsuId = new Attribute(WSConstants.WSU_PREFIX + ":Id", WSConstants.WSU_NAMESPACE, "_4");
	        	wsa.addAttribute(wsuId);
	        	Element wsaAddress = new Element(WSConstants.WSA_PREFIX + ":Address", WSConstants.WSA_NAMESPACE_05_08);
	        	wsaAddress.appendChild("http://www.w3.org/2005/08/addressing/anonymous");
	        	wsa.appendChild(wsaAddress);
	        	soapHeader.appendChild(wsa);
	        	references.add(new Reference(wsa, wsuId.getValue(), null, "SHA"));
        	}
        	{
//        		<wsse:Security S:mustUnderstand="1">
        		Element wsse = new Element(WSConstants.WSSE_PREFIX + ":Security", WSConstants.WSSE_NAMESPACE_OASIS_10);
        		{
		        	Attribute attribute = new Attribute(WSConstants.SOAP_PREFIX + ":mustUnderstand", WSConstants.SOAP11_NAMESPACE, "1");
		        	wsse.addAttribute(attribute);
        		}
        		{
//        			<wsu:Timestamp wsu:Id="_6">
//        			<wsu:Created>2004-10-18T09:02:00Z</wsu:Created>
//        			<wsu:Expires>2004-10-18T09:12:00Z</wsu:Expires>
//        			</wsu:Timestamp>
        			Element wsuTimestamp = new Element(WSConstants.WSU_PREFIX + ":Timestamp", WSConstants.WSU_NAMESPACE);
    	        	Attribute wsuId = new Attribute(WSConstants.WSU_PREFIX + ":Id", WSConstants.WSU_NAMESPACE, "_6");
    	        	wsuTimestamp.addAttribute(wsuId);
        			Element wsuCreated = new Element(WSConstants.WSU_PREFIX + ":Created", WSConstants.WSU_NAMESPACE);
        			XSDDateTime created = new XSDDateTime(-5);
        			wsuCreated.appendChild(created.getDateTime());
        			Element wsuExpires = new Element(WSConstants.WSU_PREFIX + ":Expires", WSConstants.WSU_NAMESPACE);
        			XSDDateTime expires = new XSDDateTime(5);
        			wsuExpires.appendChild(expires.getDateTime());
        			wsuTimestamp.appendChild(wsuCreated);
        			wsuTimestamp.appendChild(wsuExpires);
        			wsse.appendChild(wsuTimestamp);
        			references.add(new Reference(wsuTimestamp, wsuId.getValue(), null, "SHA"));
        		}
        		wsse.appendChild(encryptedSamlAssertion);
        		soapHeader.appendChild(wsse);
        	}
        }
        BaseEnvelopedSignature headerSigner = new BaseEnvelopedSignature(keyInfo, privateKey, "_40");
        Signature primarySignature = headerSigner.signNodes(soapHeader, references);
        Element primarySignatureElement = primarySignature.serialize();
        Reference primarySignaturReference = new Reference(primarySignatureElement, "_40", null, "SHA");
        List<Reference> ref = new ArrayList<Reference>();
        ref.add(primarySignaturReference);
        
        BaseEnvelopedSignature signatureSigner = new BaseEnvelopedSignature(samlTokenKeyInfo, privateKey, "_43");
        signatureSigner.signNodes(soapHeader, ref);
        
        BaseEnvelopedSignature signatureSigner2 = new BaseEnvelopedSignature(keyInfo, privateKey, "_46");
        signatureSigner2.signNodes(soapHeader, ref);
        
        Element soapBody = new Element(WSConstants.SOAP_PREFIX + ":Body", WSConstants.SOAP11_NAMESPACE);
        org.xmldap.ws.trust.RequestSecurityToken wstRst = new org.xmldap.ws.trust.RequestSecurityToken("http://schemas.xmlsoap.org/ws/2005/02/trust/Issue");
        wstRst.setTokenType("urn:oasis:names:tc:SAML:1.0:assertion");
        wstRst.setKeyType("http://schemas.xmlsoap.org/ws/2005/02/trust/PublicKey");
        soapEnvelope.appendChild(soapHeader);
        soapEnvelope.appendChild(soapBody);
	}

	public Element serialize() throws SerializationException {
		return soapEnvelope;
	}

	public String toXML() throws SerializationException {
		return soapEnvelope.toXML();
	}
	
	
}
