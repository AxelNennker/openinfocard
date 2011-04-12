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

import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

import nu.xom.Element;

import org.xmldap.exceptions.SerializationException;
import org.xmldap.exceptions.SigningException;
import org.xmldap.saml.Attribute;
import org.xmldap.saml.AttributeStatement;
import org.xmldap.saml.AudienceRestrictionCondition;
import org.xmldap.saml.Conditions;
import org.xmldap.saml.SAMLAssertion;
import org.xmldap.saml.Subject;
import org.xmldap.util.RandomGUID;
import org.xmldap.xml.Serializable;
import org.xmldap.xmldsig.BaseEnvelopedSignature;
import org.xmldap.xmldsig.KeyInfo;

public class ManagedToken implements Serializable {
	String mAlgorithm;
	
	//private String namespacePrefix = null;
	private String privatePersonalIdentifier;

	private String issuer;
	private String confirmationMethod = Subject.HOLDER_OF_KEY;

	private Map/*<String,String>*/supportedClaims = new HashMap/*<String,String>*/();

	//    private X509Certificate signingCert;
	    private PrivateKey signingKey;
	KeyInfo keyInfo;

	private int nowPlus = 10; //default to 10 minutes

	private int nowMinus = 10; //default to 5 minutes

	private String restrictedTo = null;
	private String relyingPartyCertB64 = null;
	
	private String tokentype = null; // FIXME support SAML2 too. This var is currently unused.
	
	public String getTokentype() {
		return tokentype;
	}

	//    public ManagedToken( X509Certificate signingCert, PrivateKey signingKey ) {
	//        this.signingCert = signingCert;
	//        this.signingKey = signingKey;
	////        namespacePrefix = org.xmldap.infocard.Constants.IC_NAMESPACE_PREFIX; // default is the new (Autumn 2006) namespace
	//    }
	public ManagedToken(KeyInfo keyInfo, PrivateKey signingKey, String tokentype, String signingAlgorithm) {
		this.keyInfo = keyInfo;
		this.signingKey = signingKey;
		this.tokentype = tokentype;
		this.mAlgorithm = signingAlgorithm;
	}

	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

	public String getIssuer() {
		return issuer;
	}

	//    public void setNamespacePrefix(String namespacePrefix) {
	//        this.namespacePrefix = namespacePrefix;
	//    }
	//
	//    public String getNamespacePrefix() {
	//    	return namespacePrefix;
	//    }

	public String getClaim(String uri) {
		return (String)supportedClaims.get(uri);
	}

	public void setClaim(String uri, String value) {
		supportedClaims.put(uri, value);
	}

	//    public int getValidityPeriod() {
	//        return nowPlus;
	//    }

	public void setValidityPeriod(int nowMinus, int nowPlus) {
		this.nowMinus = nowMinus;
		this.nowPlus = nowPlus;
	}

	public String getPrivatePersonalIdentifier() {
		return privatePersonalIdentifier;
	}

	public void setPrivatePersonalIdentifier(String privatePersonalIdentifier) {
		this.privatePersonalIdentifier = privatePersonalIdentifier;
	}

	public Element getToken(RandomGUID uuid) throws SerializationException {
		Conditions conditions = new Conditions(nowMinus, nowPlus);
		if (restrictedTo != null) {
			AudienceRestrictionCondition audienceRestrictionCondition = new AudienceRestrictionCondition(restrictedTo);
			conditions.setAudienceRestrictionCondition(audienceRestrictionCondition);
		}

		//SimpleKeyInfo keyInfo = new SimpleKeyInfo(signingCert);
//		AsymmetricKeyInfo keyInfo = new AsymmetricKeyInfo(signingCert);

		Subject subject = new Subject(keyInfo, confirmationMethod);

		Vector/*<Attribute>*/ attributes = new Vector/*<Attribute>*/();

		Attribute ppidAttribute = new Attribute(
				org.xmldap.infocard.Constants.IC_PRIVATEPERSONALIDENTIFIER,
				org.xmldap.infocard.Constants.IC_NAMESPACE,
				privatePersonalIdentifier);
		attributes.add(ppidAttribute);

		Set uriSet = supportedClaims.keySet();
		{
			Iterator iter = uriSet.iterator();
			while (iter.hasNext()) {
				String uri = (String)iter.next();
				String value = (String)supportedClaims.get(uri);
				if ((value != null) && (!"".equals(value))) {
					String name;
					int lastSlash = uri.lastIndexOf('/');
					if (lastSlash > -1) {
						name = uri.substring(lastSlash + 1);
						if (name.length() == 0) {
							name = uri;
							uri = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
						}
					} else {
						name = uri;
						uri = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
					}
                    Attribute attr = new Attribute(name, uri, value);
					attributes.add(attr);
				}
			}
		}
		AttributeStatement statement = new AttributeStatement();
		statement.setSubject(subject);

		{
			Iterator iter = attributes.iterator();
			while (iter.hasNext()) {
	
				statement.addAttribute((Attribute) iter.next());
	
			}
		}

		SAMLAssertion assertion = new SAMLAssertion(uuid);
		assertion.setIssuer(issuer);
		assertion.setConditions(conditions);
		assertion.setAttributeStatement(statement);

		//make this support multiple signing modes
		BaseEnvelopedSignature signer = new BaseEnvelopedSignature(keyInfo, signingKey, mAlgorithm);

		Element signedXML = null;
		try {
			signedXML = signer.sign(assertion.serialize());
		} catch (SigningException e) {
			throw new SerializationException("Error signing assertion", e);
		}

		return signedXML;

	}

	public String toXML() throws SerializationException {

		Element sit = serialize();
		return sit.toXML();

	}

	public Element serialize() throws SerializationException {
		//TODO - clean up hack
		return null;

	}

	public Element serialize(RandomGUID uuid) throws SerializationException {
		return getToken(uuid);
	}

	public String getConfirmationMethod() {
		return confirmationMethod;
	}

	public void setConfirmationMethod(String confirmationMethod) {
		this.confirmationMethod = confirmationMethod;
	}

	public String getRestrictedTo() {
		return restrictedTo;
	}

	public String getRelyingPartyCertB64() {
		return relyingPartyCertB64;
	}

	public void setRestrictedTo(String restrictedTo, String relyingPartyCertB64) {
		this.restrictedTo = restrictedTo;
		this.relyingPartyCertB64 = relyingPartyCertB64;
	}

}
