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

package org.xmldap.ws.soap.headers.addressing;

import java.security.cert.X509Certificate;

import nu.xom.Element;
import nu.xom.Elements;

import org.xmldap.exceptions.ParsingException;
import org.xmldap.exceptions.SerializationException;
import org.xmldap.ws.WSConstants;
import org.xmldap.xml.Serializable;
import org.xmldap.xmldsig.InfocardKeyInfo;
import org.xmldap.xmldsig.ParsedKeyInfo;

/**
 * Created by IntelliJ IDEA.
 * User: cmort
 * Date: Mar 25, 2006
 * Time: 2:34:45 PM
 * To change this template use File | Settings | File Templates.
 */
public class IdentityEnabledEndpointReference extends EndpointReference implements Serializable {

    private X509Certificate cert = null;

//    public IdentityEnabledEndpointReference(String sts, String mex) {
//        super(sts, mex);
//        cert = null;
//    }

    public IdentityEnabledEndpointReference(String sts, String mex, X509Certificate cert) {
        super(sts, mex);
        this.cert = cert;
    }

    public IdentityEnabledEndpointReference(Element elt) throws ParsingException {
    	super(elt);
    	
    	Elements elts = elt.getChildElements("Identity", WSConstants.WSA_ID_06_02);
    	if (elts != null && elts.size() == 1) {
    		Element identityElt = elts.get(0);
    		elts = identityElt.getChildElements("KeyInfo", WSConstants.DSIG_NAMESPACE);
    		if (elts != null && elts.size() == 1) {
    			Element keyinfo = elts.get(0);
    			ParsedKeyInfo parsedKeyInfo = new ParsedKeyInfo(keyinfo);
    			cert = parsedKeyInfo.getParsedX509Data().getCertificates().get(0);
    		} else {
    			throw new ParsingException("IdentityEnabledEndpointReference: only KeyInfo as Identity is implemented. " + identityElt.toXML());
    		}
    	} // else optional
    }

    private Element getIEPR() throws SerializationException {

        Element ref = getEPR();
        if (cert != null) {
	        Element identity = new Element(WSConstants.WSA_ID_PREFIX + ":Identity", WSConstants.WSA_ID_06_02);
	
	        //AsymmetricKeyInfo keyInfo = new AsymmetricKeyInfo(cert);
	        InfocardKeyInfo keyInfo = new InfocardKeyInfo(cert);
	        identity.appendChild(keyInfo.serialize());
	        ref.appendChild(identity);
        }
        return ref;

    }

    public X509Certificate getCert() {
    	return cert;
    }
    
    public String toXML() throws SerializationException {

        Element iepr = serialize();
        return iepr.toXML();

    }


    public Element serialize() throws SerializationException {


        return getIEPR();

    }

}
