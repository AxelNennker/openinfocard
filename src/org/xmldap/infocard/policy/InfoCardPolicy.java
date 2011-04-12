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

package org.xmldap.infocard.policy;

import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import nu.xom.Element;

import org.xmldap.exceptions.SerializationException;
import org.xmldap.ws.WSConstants;
import org.xmldap.xml.Serializable;

public class InfoCardPolicy implements Serializable {


    Vector supportedTokens = new Vector();
    Vector supportedClaims = new Vector();

    public void addSupportedToken(SupportedToken token) {

        supportedTokens.add(token);

    }

    public void addSupportedClaim(SupportedClaim claim) {

        supportedClaims.add(claim);

    }

    public List getSupportedTokens() {
        return supportedTokens;
    }

    public List getSupportedClaims() {
        return supportedClaims;
    }


    private Element getInfoCardPolicy() throws SerializationException {


        Element supportedTokenTypeList = new Element(WSConstants.INFOCARD_PREFIX + ":SupportedTokenTypeList", WSConstants.INFOCARD_NAMESPACE);


        Iterator tokens = getSupportedTokens().iterator();
        while (tokens.hasNext()) {

            SupportedToken token = (SupportedToken) tokens.next();
            supportedTokenTypeList.appendChild(token.serialize());

        }


        Element supportedClaimTypeList = new Element(WSConstants.INFOCARD_PREFIX + ":SupportedClaimTypeList", WSConstants.INFOCARD_NAMESPACE);

        Iterator claims = getSupportedClaims().iterator();
        while (claims.hasNext()) {

            SupportedClaim claim = (SupportedClaim) claims.next();
            supportedClaimTypeList.appendChild(claim.serialize());

        }

        //TODO - THIS CLASS IS DEPRECATED   - wait to remove from SVN when I cleanup

        return null;
    }

    public String toXML() throws SerializationException {

        Element policy = serialize();
        return policy.toXML();

    }

    public Element serialize() throws SerializationException {
        return getInfoCardPolicy();
    }
}
