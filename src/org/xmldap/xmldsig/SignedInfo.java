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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import nu.xom.Attribute;
import nu.xom.Element;
import nu.xom.canonical.Canonicalizer;

import org.xmldap.crypto.CryptoUtils;
import org.xmldap.exceptions.SerializationException;
import org.xmldap.xml.Canonicalizable;
import org.xmldap.xml.XmlUtils;

/**
 * Created by IntelliJ IDEA.
 * User: cmort
 * Date: Mar 20, 2006
 * Time: 10:58:21 PM
 * To change this template use File | Settings | File Templates.
 */
public class SignedInfo implements Canonicalizable {

	String mAlgorithm;
	
	protected String defaultCanonicalizationMethod = Canonicalizer.EXCLUSIVE_XML_CANONICALIZATION;
	
    //TODO - support multiple C14n types
    List references = null;

    String inclusiveNamespacePrefixes = null;
    
    public String getAlgorithm() {
    	return mAlgorithm;
    }
    
    public SignedInfo(List references, String signingAlgorithm) {
        this.references = references;
        this.mAlgorithm = signingAlgorithm;
    }

    public SignedInfo(Reference reference, String inclusiveNamespacePrefixes, String signingAlgorithm) {
        this.references = new ArrayList();
        references.add(reference);
        this.inclusiveNamespacePrefixes = inclusiveNamespacePrefixes;
        this.mAlgorithm = signingAlgorithm;
    }

    public SignedInfo(Reference reference, String signingAlgorithm) {
        this.references = new ArrayList();
        references.add(reference);
        this.inclusiveNamespacePrefixes = null;
        this.mAlgorithm = signingAlgorithm;
    }

    protected SignedInfo() {}
    
    public void setInclusiveNamespacePrefixList(String inclusiveNamespacePrefixes) 
    {
    	this.inclusiveNamespacePrefixes = inclusiveNamespacePrefixes;
   }
    
    public Element getSignedInfo() throws SerializationException {

        
        //TODO - handle ID References!
        //RandomGUID guidGen = new RandomGUID();
        //String guid = guidGen.toURN();

        Element signedInfo = new Element("dsig:SignedInfo", "http://www.w3.org/2000/09/xmldsig#");
        //signedInfo.addNamespaceDeclaration(WSConstants.WSU_PREFIX, WSConstants.WSSE_OASIS_10_WSU_NAMESPACE);
        //Attribute idAttr = new Attribute(WSConstants.WSU_PREFIX + ":Id", WSConstants.WSSE_OASIS_10_WSU_NAMESPACE, guid);
        //signedInfo.addAttribute(idAttr);

        Element canonicalizationMethod = new Element("dsig:CanonicalizationMethod", "http://www.w3.org/2000/09/xmldsig#");
        Attribute canonAlgorithm = new Attribute("Algorithm", defaultCanonicalizationMethod);
        canonicalizationMethod.addAttribute(canonAlgorithm);
        if (inclusiveNamespacePrefixes != null) {
        	// <ec:InclusiveNamespaces PrefixList="dsig soap #default" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        	Element inclusiveNamespacePrefixesE = new Element("ec:InclusiveNamespaces","http://www.w3.org/2001/10/xml-exc-c14n#");
        	Attribute prefixList = new Attribute("PrefixList", inclusiveNamespacePrefixes);
        	inclusiveNamespacePrefixesE.addAttribute(prefixList);
        	canonicalizationMethod.appendChild(inclusiveNamespacePrefixesE);
        }
        signedInfo.appendChild(canonicalizationMethod);

        Element signatureMethod = new Element("dsig:SignatureMethod", "http://www.w3.org/2000/09/xmldsig#");
        String algorithm = CryptoUtils.convertSigningAlgorithm(mAlgorithm);
        Attribute signAlgo = new Attribute("Algorithm", algorithm);
        signatureMethod.addAttribute(signAlgo);
        signedInfo.appendChild(signatureMethod);

        try {
            Iterator refIter = references.iterator();
            while (refIter.hasNext()) {

                Reference thisReference = (Reference) refIter.next();
                signedInfo.appendChild(thisReference.serialize());

            }
        } catch (SerializationException e) {
        	throw new SerializationException(e);
        }

        return signedInfo;

    }


    public byte[] canonicalize() throws SerializationException {
        return canonicalize(defaultCanonicalizationMethod);
    }

    public byte[] canonicalize(String canonicalizationAlgorithm) throws SerializationException {
    	try {
			return XmlUtils.canonicalize(serialize(), canonicalizationAlgorithm);
		} catch (IOException e) {
			throw new SerializationException(e);
		}
    }

    public String toXML() throws SerializationException {
        Element sigVal = serialize();
        return sigVal.toXML();
    }

    public Element serialize() throws SerializationException {
        return getSignedInfo();  //To change body of implemented methods use File | Settings | File Templates.
    }
}
