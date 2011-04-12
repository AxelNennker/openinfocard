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
import java.security.PrivateKey;
import java.util.List;
import java.util.Vector;

import nu.xom.Attribute;
import nu.xom.Document;
import nu.xom.Element;
import nu.xom.Nodes;
import nu.xom.ParentNode;

import org.xmldap.crypto.CryptoUtils;
import org.xmldap.exceptions.CryptoException;
import org.xmldap.exceptions.SerializationException;
import org.xmldap.exceptions.SigningException;
import org.xmldap.ws.WSConstants;
import org.xmldap.xml.Canonicalizable;
import org.xmldap.xml.XmlUtils;


public class BaseEnvelopedSignature {
  String mAlgorithm;

//    private X509Certificate signingCert;
    protected PrivateKey privateKey;
  protected KeyInfo keyInfo;
  protected String Id = null;
  
//    public EnvelopedSignature(X509Certificate signingCert, PrivateKey privateKey) {
//        this.privateKey = privateKey;
//        this.signingCert = signingCert;
//    }
    public BaseEnvelopedSignature(KeyInfo keyInfo, PrivateKey privateKey, String signingAlgorithm) {
        this.keyInfo = keyInfo;
        this.privateKey = privateKey;
        this.mAlgorithm = signingAlgorithm;
    }

    public BaseEnvelopedSignature(KeyInfo keyInfo, PrivateKey privateKey, String Id, String signingAlgorithm) {
        this.keyInfo = keyInfo;
        this.privateKey = privateKey;
        this.Id = Id;
        this.mAlgorithm = signingAlgorithm;
    }

    protected BaseEnvelopedSignature() {}
    
  /**
   * @param xml
   * @param nodesToReference
   * @throws SigningException
   * @return a signed copy of this element
   */
  public Element sign(Element xml) throws SigningException {
        Element signThisOne = (Element) xml.copy();

        String prefixes = null;
        {
          StringBuilder sb = null;
          for (int i=0; i<signThisOne.getNamespaceDeclarationCount(); i++) {
            String prefix = signThisOne.getNamespacePrefix(i);
            if ("".equals(prefix)) {
              prefix ="#default";
            }
            if (sb == null) {
              sb = new StringBuilder();
              sb.append(prefix);
            } else {
              sb.append(" ");
              sb.append(prefix);
            }
          }
          if (sb != null) {
            prefixes = sb.toString();
          }
        }
        
      String idVal = signThisOne.getAttributeValue("Id", WSConstants.WSSE_OASIS_10_WSU_NAMESPACE);
        if (idVal == null) {
            //let's see if its a SAML assertions
            Attribute assertionID = signThisOne.getAttribute("AssertionID");
            if (assertionID != null) {
                idVal = assertionID.getValue();
            }
        }
        if (idVal == null) {
          throw new IllegalArgumentException("BaseEnvelopedSignature: Element to sign does not have an id-ttribute");
        }
    Reference reference = new Reference(signThisOne, idVal, prefixes, "SHA1");
    
        //Get SignedInfo for reference
        SignedInfo signedInfo = new SignedInfo(reference, mAlgorithm);

        Signature signature = getSignatureValue(signedInfo);

        //Envelope it.
        try {
          signThisOne.appendChild(signature.serialize());
        } catch (SerializationException e) {
            throw new SigningException("Could not create enveloped signature due to serialization error", e);
        }
        return signThisOne;
  }

  /**
   * @param xml
   * @param nodesToReference
   * @return Signture Element
   * @throws SigningException
   */
  public Signature signNodes(Element xml, List references) throws SigningException {

        //Get SignedInfo for reference
        SignedInfo signedInfo = new SignedInfo(references, mAlgorithm);

        Signature signature = getSignatureValue(signedInfo);

        //Envelope it.
        try {
            //Element rootElement = xml.getRootElement();
            //rootElement.appendChild(signature.serialize());
            xml.appendChild(signature.serialize());
        } catch (SerializationException e) {
            throw new SigningException("Could not create enveloped signature due to serialization error", e);
        }
        return signature;
  }
  
  /**
   * @param nodesToReference
   * @return
   * @throws SigningException
   */
  private Vector getReferences(Nodes nodesToReference) throws SigningException {
    Vector references = new Vector();

        for (int i = 0; i < nodesToReference.size(); i++) {

            try {


                Element referenceThis = (Element) nodesToReference.get(i);
                //Check for root
                boolean isRoot = false;
                Document thisDoc = referenceThis.getDocument();

                //TODO - common code
                //it isn't a doc, let's check if it's the top of the tree.
                if (thisDoc == null) {

                    ParentNode parent = referenceThis.getParent();
                    if (parent == null) isRoot = true;

                } else {

                    //It is a doc - let's see if it's root.
                    Element root = thisDoc.getRootElement();
                    if (root.equals(referenceThis)) isRoot = true;

                }

                //Attribute id = referenceThis.getAttribute("Id",WSConstants.WSSE_OASIS_10_WSU_NAMESPACE);

                String idVal = "";

                if (!isRoot) {
                    //TODO - support multiple ID id Ids
                    Attribute id = referenceThis.getAttribute("id");
                    if (id == null)
                        throw new SigningException("XPath returned Element with no wsu:Id attribute. Id is required");
                    idVal = id.getValue();
                    //System.out.println("Building reference for ID " + id.getValue() + ": " + referenceThis);
                } else {

                    //let's see if its a SAML assertions
                    Attribute assertionID = referenceThis.getAttribute("AssertionID");
                    if (assertionID != null) {

                        idVal = assertionID.getValue();

                    }

                }

                Reference referenceElm = new Reference(referenceThis, idVal, null, "SHA");

                references.add(referenceElm);

            } catch (ClassCastException e) {

                throw new SigningException("XPath returned an item which was not an element. Signing only allowed on elements.", e);

            }

        }
    return references;
  }

  /**
   * @param xml
   * @param nodesToReference
   * @throws SigningException
   */
  public void signNodes(Element xml, Nodes nodesToReference) throws SigningException {
    Vector references = getReferences(nodesToReference);
    signNodes(xml, references);
  }

  /**
   * @param signedInfo
   * @return
   */
  protected Signature getSignatureValue(SignedInfo signedInfo) {
    //Get sigvalue for the signedInfo
        SignatureValue signatureValue = new SignatureValue(signedInfo, privateKey);

        //Get KeyInfo
//        KeyInfo keyInfo = new AsymmetricKeyInfo(signingCert);


        //Create the signature block
        Signature signature = new Signature(signedInfo, signatureValue, keyInfo);
    return signature;
  }

  protected static byte[] getAssertionCanonicalBytes(Element r00t) throws IOException {
    // make a deep copy because we don not want to modify the parameter
    Element root = (Element)r00t.copy();
    
    // REMOVE the siganture element
    Element signature = root.getFirstChildElement("Signature",
        WSConstants.DSIG_NAMESPACE);
    // System.out.println(signature.toXML());
    if (signature != null) {
      root.removeChild(signature);
    }
    
    return XmlUtils.canonicalize(root, Canonicalizable.EXCLUSIVE_CANONICAL_XML);
  }

  protected static String digestElement(Element root) throws CryptoException {
    return digestElement(root, "SHA");
  }

  /**
   * @param root
   * @return
   * @throws CryptoException
   */
  protected static String digestElement(Element root, String messageDigestAlgorithm) throws CryptoException {
    String b64EncodedDigest = null;

    byte[] assertionCanonicalBytes;
    try {
      assertionCanonicalBytes = getAssertionCanonicalBytes(root);
    } catch (IOException e) {
      throw new CryptoException(e);
    }

    // WE've got the canonical without the signature.
    // Let's calculate the Digest to validate the references
    try {
      b64EncodedDigest = CryptoUtils.digest(assertionCanonicalBytes, messageDigestAlgorithm);
    } catch (CryptoException e) {
      throw new CryptoException(e);
    }
    return b64EncodedDigest;
  }

}
