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

package org.xmldap.ws.soap.headers.security;

import java.util.Iterator;
import java.util.Vector;

import nu.xom.Element;

import org.xmldap.exceptions.SerializationException;
import org.xmldap.ws.WSConstants;

/**
 * Created by IntelliJ IDEA.
 * User: cmort
 * Date: Mar 16, 2006
 * Time: 6:56:25 PM
 * To change this template use File | Settings | File Templates.
 */
public class WSSEHeaderImpl implements WSSEHeader {

    protected Vector tokens = new Vector();
    private boolean mustUnderstand = false;

    public void addToken(WSSEToken token) {

        tokens.add(token);

    }

    public void setMustUnderstand(boolean mustUnderstand) {
        this.mustUnderstand = mustUnderstand;
    }


    public String toXML() throws SerializationException {

        Element header = serialize();
        return header.toXML();

    }

    public Element serialize() throws SerializationException {

        Element token = new Element(WSConstants.WSSE_PREFIX + ":Security", WSConstants.WSSE_NAMESPACE_OASIS_10);

        if (mustUnderstand) {

            //TODO - figure out how to do the mustUnderstand in this case, when I don't know the envelope namepsace
            //Attribute mustUnder = new Attribute("soap:mustUnderstand", WSConstants.)

        }

        Iterator tokenIter = tokens.iterator();
        while (tokenIter.hasNext()) {

            WSSEToken thisToken = (WSSEToken) tokenIter.next();
            token.appendChild(thisToken.serialize());

        }

        return token;

    }
}
