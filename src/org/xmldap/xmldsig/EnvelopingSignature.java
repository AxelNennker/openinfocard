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

package org.xmldap.xmldsig;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Vector;

import nu.xom.Attribute;
import nu.xom.Element;

import org.xmldap.exceptions.SerializationException;
import org.xmldap.exceptions.SigningException;
import org.xmldap.util.RandomGUID;
import org.xmldap.ws.WSConstants;


public class EnvelopingSignature {

	String mAlgorithm;
    private X509Certificate cert;
    private PrivateKey privateKey;

    public EnvelopingSignature(X509Certificate cert, PrivateKey privateKey, String signingAlgorithm) {
        this.cert = cert;
        this.privateKey = privateKey;
        this.mAlgorithm = signingAlgorithm;
    }

    public Element sign(Element xml) throws SigningException {

        Element object = new Element(WSConstants.DSIG_PREFIX + ":Object", WSConstants.DSIG_NAMESPACE);
        RandomGUID guidGen = new RandomGUID();
        Attribute id = new Attribute("Id", guidGen.toURN());
        object.addAttribute(id);
        object.appendChild(xml);

        Reference referenceElm = new Reference(object, id.getValue(), null, "SHA");
        referenceElm.setEnveloped(false);

        Vector references = new Vector();
        references.add(referenceElm);

        //Get SignedInfo for reference
        SignedInfo signedInfo = new SignedInfo(references, mAlgorithm);

        //Get sigvalue for the signedInfo
        SignatureValue signatureValue = new SignatureValue(signedInfo, privateKey);

        //Get AsymmetricKeyInfo
        AsymmetricKeyInfo keyInfo = new AsymmetricKeyInfo(cert);


        //Create the signature block
        Signature signature = new Signature(signedInfo, signatureValue, keyInfo);

        Element signatureElement = null;

        //Envelope it.
        try {

            signatureElement = signature.serialize();

        } catch (SerializationException e) {
            throw new SigningException("Could not create signature due to serialization error", e);
        }

        signatureElement.appendChild(object);

        return signatureElement;

    }


}
