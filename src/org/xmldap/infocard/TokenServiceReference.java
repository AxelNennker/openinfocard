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

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import nu.xom.Element;
import nu.xom.Elements;

import org.json.JSONException;
import org.json.JSONObject;
import org.xmldap.exceptions.ParsingException;
import org.xmldap.exceptions.SerializationException;
import org.xmldap.ws.WSConstants;
import org.xmldap.ws.soap.headers.addressing.EndpointReference;
import org.xmldap.ws.soap.headers.addressing.IdentityEnabledEndpointReference;
import org.xmldap.xml.Serializable;


public class TokenServiceReference implements Serializable {

//    private String address;
//    private String mexAddress;

    UserCredential userCredential = null;

//    private X509Certificate cert;

    private List<EndpointReference> epList = null;

//    public TokenServiceReference() {
//    }

//    public TokenServiceReference(String address, String mexAddress) {
//    	IdentityEnabledEndpointReference epr = new IdentityEnabledEndpointReference(address, mexAddress);
//    	epList = new ArrayList<IdentityEnabledEndpointReference>(1);
//    	epList.add(epr);
//    }

    public TokenServiceReference(
    		String address, String mexAddress, X509Certificate cert, UserCredential userCredential) {
    	IdentityEnabledEndpointReference epr = new IdentityEnabledEndpointReference(address, mexAddress, cert);
    	epList = new ArrayList<EndpointReference>(1);
    	epList.add(epr);
    	this.userCredential = userCredential;
    }

    public TokenServiceReference(Element tokenServiceReference) throws ParsingException {
    	String name = tokenServiceReference.getLocalName();
    	if ("TokenService".equals(name)) {
    		Elements elts = tokenServiceReference.getChildElements("EndpointReference", WSConstants.WSA_NAMESPACE_05_08);
    		if (elts.size() == 1) {
    			Element elt = elts.get(0);
    			EndpointReference epr = new IdentityEnabledEndpointReference(elt);
    			if (epList == null) {
    				epList = new ArrayList<EndpointReference>();
    			}
    			epList.add(epr);
    		} else {
    			throw new ParsingException("Expected one occurence of EndpointReference but found: " + elts.size());
    		}
    		elts = tokenServiceReference.getChildElements("UserCredential", WSConstants.INFOCARD_NAMESPACE);
    		if (elts.size() == 1) {
    			Element elt = elts.get(0);
    			userCredential = new UserCredential(elt);
    		} else {
    			throw new ParsingException("Expected one occurence of UserCredential but found: " + elts.size());
    		}
    	} else {
    		throw new ParsingException("Expected TokenService but found: " + name);
    	}
    }
    
    public TokenServiceReference(JSONObject json) throws JSONException {
      EndpointReference epr = new EndpointReference(json.getJSONObject("EndpointReference"));
      epList = new ArrayList<EndpointReference>();
      epList.add(epr);
      userCredential = new UserCredential(json.getJSONObject("UserCredential"));
    }
    
    public String getMexAddress() {
    	EndpointReference epr = epList.get(0);
    	return epr.getMexAddress();
    }

    public void setMexAddress(String mexAddress) {
    	EndpointReference epr = epList.get(0);
    	epr.setMexAddress(mexAddress);
    }

    public X509Certificate getCert() {
    	IdentityEnabledEndpointReference epr = (IdentityEnabledEndpointReference)epList.get(0);
        return epr.getCert();
    }

    public String getAddress() {
    	EndpointReference epr = epList.get(0);
        return epr.getAddress();
    }

    public void setAddress(String address) {
    	EndpointReference epr = epList.get(0);
        epr.setAddress(address);
    }

    public void setAuthType(String authType, String value) {
    	userCredential = new UserCredential(authType, value);
    }
    
    public UserCredential getUserCredential() {
    	return userCredential;
    }
    
    private Element getTokenServiceReference() throws SerializationException {

        //TODO - support all the reference types
        Element tokenService = new Element(WSConstants.INFOCARD_PREFIX + ":TokenService", WSConstants.INFOCARD_NAMESPACE);
        EndpointReference iepr = epList.get(0);
        tokenService.appendChild(iepr.serialize());

        Element userCredentialElt = userCredential.serialize();
        tokenService.appendChild(userCredentialElt);
        return tokenService;

    }


    public JSONObject toJSON() throws SerializationException {
      try {
        JSONObject json = new JSONObject();
        json.put("EndpointReference", epList.get(0).toJSON());
        json.put("UserCredential", userCredential.toJSON());
        return json;
      } catch (JSONException e) {
        throw new SerializationException(e);
      }
    }


    public String toXML() throws SerializationException {

        Element tsr = getTokenServiceReference();
        return tsr.toXML();

    }

    public Element serialize() throws SerializationException {
        return getTokenServiceReference();
    }


}
