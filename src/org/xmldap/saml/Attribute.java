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

package org.xmldap.saml;

import nu.xom.Element;

import org.xmldap.exceptions.SerializationException;
import org.xmldap.ws.WSConstants;
import org.xmldap.xml.Serializable;


public class Attribute implements Serializable {


    private String attributeName;
    private String attributeNamespace;
    private String value;

    public Attribute(String attributeName, String attributeNamespace, String value) {
        this.attributeName = attributeName;
        this.attributeNamespace = attributeNamespace;
        this.value = value;
    }

    private Element getAttribute() {
        Element attribute = new Element(WSConstants.SAML_PREFIX + ":Attribute", WSConstants.SAML11_NAMESPACE);
        nu.xom.Attribute attrName = new nu.xom.Attribute("AttributeName", attributeName);
        nu.xom.Attribute attrNamespace = new nu.xom.Attribute("AttributeNamespace", attributeNamespace);
        attribute.addAttribute(attrName);
        attribute.addAttribute(attrNamespace);
        Element attributeValue = new Element(WSConstants.SAML_PREFIX + ":AttributeValue", WSConstants.SAML11_NAMESPACE);
        attributeValue.appendChild(value);
        attribute.appendChild(attributeValue);
        return attribute;
    }


    public Element serialize() throws SerializationException {

        return getAttribute();

    }

    public String toXML() throws SerializationException {

        Element attr = serialize();
        return attr.toXML();

    }

    public static void main(String[] args) {

        Attribute given = new Attribute("givenname", "http://schemas.microsoft.com/ws/2005/05/identity/claims/GivenName", "Chuck");
        Attribute sur = new Attribute("surname", "http://schemas.microsoft.com/ws/2005/05/identity/claims/SurName", "Mortimore");
        Attribute email = new Attribute("givenname", "http://schemas.microsoft.com/ws/2005/05/identity/claims/EmailAddress", "cmortspam@gmail.com");

        try {
            System.out.println(given.toXML());
            System.out.println(sur.toXML());
            System.out.println(email.toXML());
        } catch (SerializationException e) {
            e.printStackTrace();
        }


    }
}
