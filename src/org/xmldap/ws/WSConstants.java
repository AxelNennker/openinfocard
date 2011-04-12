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

package org.xmldap.ws;


public interface WSConstants {

    public static final String SOAP11_NAMESPACE = "http://schemas.xmlsoap.org/soap/envelope/";
    public static final String SOAP12_NAMESPACE = "http://www.w3.org/2003/05/soap-envelope";
    public static final String SOAP_PREFIX = "soap";

    static final String WSA_NAMESPACE_04_08 = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
    static final String WSA_NAMESPACE_05_08 = "http://www.w3.org/2005/08/addressing";
    //    http://www.w3.org/2006/03/addressing/ws-addr.xsd.
    static final String WSA_NAMESPACE_06_03 = "http://www.w3.org/2006/03/addressing";

    static final String WSA_PREFIX = "wsa";

    static final String WSSE_NAMESPACE_OASIS_10 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    static final String WSSE_NAMESPACE_OASIS_11 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.1.xsd";
    static final String WSSE_PREFIX = "wsse";

    static final String WSSE_OASIS_10_PASSWORD_TEXT = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText";
    static final String WSSE_OASIS_10_PASSWORD_DIGEST = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest";

    static final String WSSE_OASIS_XX_THUMBPRINTSHA1 = "http://docs.oasis-open.org/wss/2004/xx/oasis-2004xx-wss-soap-message-security-1.1#ThumbprintSHA1";
    static final String WSSE_OASIS_XX_BASE64BINARY = "http://docs.oasis-open.org/wss/2004/xx/oasis-2004xx-wss-soap-message-security-1.1#Base64Binary";
    
    static final String WSSE_OASIS_10_WSU_NAMESPACE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    static final String WSU_PREFIX = "wsu";
    static final String WSU_NAMESPACE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

//    public final static String POLICY_NAMESPACE_02_12 = "http://schemas.xmlsoap.org/ws/2002/12/policy";
    public final static String POLICY_NAMESPACE_04_09 = "http://schemas.xmlsoap.org/ws/2004/09/policy";
    public final static String POLICY_PREFIX = "wsp";

    public final static String TRUST_NAMESPACE_05_02 = "http://schemas.xmlsoap.org/ws/2005/02/trust";
    public final static String TRUST_NAMESPACE_04_04 = "http://schemas.xmlsoap.org/ws/2004/04/trust";
    public final static String TRUST_PREFIX = "wst";

    public final static String RST_ISSUE_TYPE_05_02 = "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue";
    public final static String RST_ISSUE_TYPE_04_04 = "http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue";
    public final static String RST_ACTION_04_04 = "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RST/Issue";

    public final static String SECURITY_POLICY_05_07 = "http://schemas.xmlsoap.org/ws/2005/07/securitypolicy";

    //public final static String SAML11_NAMESPACE  = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLAssertionID";
    public final static String SAML11_NAMESPACE = "urn:oasis:names:tc:SAML:1.0:assertion";
    public final static String WSS_SAML11_NAMESPACE = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1";
    public final static String SAML20_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:assertion";
    public final static String SAML_PREFIX = "saml";

    public final static String INFOCARD = "http://schemas.microsoft.com/ws/2005/05/identity";

    public final static String MEX_04_08 = "http://schemas.xmlsoap.org/ws/2004/08/mex";
    public final static String MEX_04_09 = "http://schemas.xmlsoap.org/ws/2004/09/mex";
    public final static String MEX_PREFIX = "mex";

    public final static String DSIG_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#";
    public final static String DSIG_PREFIX = "ds";

    public final static String ENC_NAMESPACE = "http://www.w3.org/2001/04/xmlenc#";
    public final static String ENC_PREFIX = "enc";

    public final static String INFOCARD_NAMESPACE = "http://schemas.xmlsoap.org/ws/2005/05/identity";
    public final static String INFOCARD_PREFIX = "ic";
    public final static String INFOCARD07_NAMESPACE = "http://schemas.xmlsoap.org/ws/2007/01/identity";
    public final static String INFOCARD07_PREFIX = "ic07";
    public final static String INFOCARD09_NAMESPACE = "http://docs.oasis-open.org/imi/ns/identity-200903";
    public final static String INFOCARD09_PREFIX = "ic09";
    public final static String INFOCARD11_NAMESPACE = "http://docs.oasis-open.org/imi/ns/identity-201104";
    public final static String INFOCARD11_PREFIX = "ic11";
    	
    public final static String WSA_ID_NAMESPACE = "http://schemas.microsoft.com/windows/wcf/2005/09/addressingidentityextension";
    public final static String WSA_ID_06_02 = "http://schemas.xmlsoap.org/ws/2006/02/addressingidentity";
    public final static String WSA_ID_PREFIX = "wsid";

}
