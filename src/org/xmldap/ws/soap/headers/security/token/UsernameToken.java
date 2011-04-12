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

package org.xmldap.ws.soap.headers.security.token;

import nu.xom.Attribute;
import nu.xom.Element;

import org.xmldap.exceptions.SerializationException;
import org.xmldap.util.RandomGUID;
import org.xmldap.util.XSDDateTime;
import org.xmldap.ws.WSConstants;
import org.xmldap.ws.soap.headers.security.WSSEToken;

public class UsernameToken implements WSSEToken {

    private String username = null;
    private String password = null;
    private String nonce = null;
    private String created = null;
    private String id = null;

    public UsernameToken() {
        RandomGUID guidGen = new RandomGUID();
        id = guidGen.toURN();

    }

    public UsernameToken(String userName, String password) {
        this.username = userName;
        this.password = password;
        RandomGUID guidGen = new RandomGUID();
        id = guidGen.toURN();
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getCreated() {
        return created;
    }

    public String getId() {
        return id;
    }

    public void addCreated() {

        XSDDateTime dateTime = new XSDDateTime();
        this.created = dateTime.getDateTime();

    }

    public String getNonce() {
        return nonce;
    }


    public void createNonce() {
        RandomGUID guidGen = new RandomGUID();
        this.nonce = guidGen.toString();
    }

    public String toXML() throws SerializationException {
        Element header = serialize();
        return header.toXML();
    }

    public Element serialize() throws SerializationException {

        Element token = new Element(WSConstants.WSSE_PREFIX + ":UsernameToken", WSConstants.WSSE_NAMESPACE_OASIS_10);
        token.addNamespaceDeclaration(WSConstants.WSU_PREFIX, WSConstants.WSSE_OASIS_10_WSU_NAMESPACE);
        Attribute idAttr = new Attribute(WSConstants.WSU_PREFIX + ":Id", WSConstants.WSSE_OASIS_10_WSU_NAMESPACE, id);
        token.addAttribute(idAttr);

        if (username != null) {
            Element usernameElm = new Element(WSConstants.WSSE_PREFIX + ":Username", WSConstants.WSSE_NAMESPACE_OASIS_10);
            usernameElm.appendChild(username);
            token.appendChild(usernameElm);
        }

        if (password != null) {
            Element passwordElm = new Element(WSConstants.WSSE_PREFIX + ":Password", WSConstants.WSSE_NAMESPACE_OASIS_10);
            Attribute type = new Attribute("Type", WSConstants.WSSE_OASIS_10_PASSWORD_TEXT);
            passwordElm.addAttribute(type);
            passwordElm.appendChild(password);
            token.appendChild(passwordElm);
        }

        if (nonce != null) {
            Element nonceElm = new Element(WSConstants.WSSE_PREFIX + ":Nonce", WSConstants.WSSE_NAMESPACE_OASIS_10);
            nonceElm.appendChild(nonce);
            token.appendChild(nonceElm);
        }

        if (created != null) {

            Element nonceElm = new Element(WSConstants.WSU_PREFIX + ":Created", WSConstants.WSSE_OASIS_10_WSU_NAMESPACE);
            nonceElm.appendChild(created);
            token.appendChild(nonceElm);

        }

        return token;

    }


    public Element getSecurityTokenReference() {

        /*
        <wsse:SecurityTokenReference xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><wsse:Reference URI="#ink767Hpn1fLKb78LQdNQazJKlEE"/></wsse:SecurityTokenReference>
        */
        Element str = new Element(WSConstants.WSSE_PREFIX + ":SecurityTokenReference", WSConstants.WSSE_NAMESPACE_OASIS_10);
        Element ref = new Element(WSConstants.WSSE_PREFIX + ":Reference", WSConstants.WSSE_NAMESPACE_OASIS_10);
        Attribute uri = new Attribute("URI", "#" + id);
        ref.addAttribute(uri);
        str.appendChild(ref);
        return str;
    }
}
