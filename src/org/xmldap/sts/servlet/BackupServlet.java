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


package org.xmldap.sts.servlet;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.xmldap.exceptions.KeyStoreException;
import org.xmldap.infocard.InfoCard;
import org.xmldap.infocard.TokenServiceReference;
import org.xmldap.infocard.UserCredential;
import org.xmldap.infocard.policy.SupportedClaim;
import org.xmldap.infocard.policy.SupportedClaimTypeList;
import org.xmldap.infocard.policy.SupportedToken;
import org.xmldap.infocard.policy.SupportedTokenList;
import org.xmldap.infocard.roaming.EncryptedStore;
import org.xmldap.infocard.roaming.InformationCardMetaData;
import org.xmldap.infocard.roaming.RoamingInformationCard;
import org.xmldap.infocard.roaming.RoamingStore;
import org.xmldap.infocard.roaming.SelfIssuedInformationCardPrivateData;
import org.xmldap.sts.db.CardStorage;
import org.xmldap.sts.db.DbSupportedClaim;
import org.xmldap.sts.db.ManagedCard;
import org.xmldap.sts.db.SupportedClaims;
import org.xmldap.sts.db.impl.CardStorageEmbeddedDBImpl;
import org.xmldap.util.Base64;
import org.xmldap.util.KeystoreUtil;
import org.xmldap.util.PropertiesManager;
import org.xmldap.util.XSDDateTime;
import org.xmldap.ws.WSConstants;


public class BackupServlet extends HttpServlet {

    private static CardStorage storage = null;
    private String base64ImageFile = null;

    private X509Certificate cert = null;
    private String domainname = null;
    private String servletPath = null;
    private SupportedClaims supportedClaimsImpl = null;

    long privacyPolicyVersion = 1; // TODO make this a property

    public void init(ServletConfig config) throws ServletException {

        super.init(config);

        try {

            PropertiesManager properties = new PropertiesManager(PropertiesManager.SECURITY_TOKEN_SERVICE, config.getServletContext());
            String keystorePath = properties.getProperty("keystore");
            String keystorePassword = properties.getProperty("keystore.password");
            String key = properties.getProperty("key.name");
//            String keyPassword = properties.getProperty("key-password");
            String supportedClaimsClass = properties.getProperty("supportedClaimsClass");
            supportedClaimsImpl = SupportedClaims.getInstance(supportedClaimsClass);
            storage = new CardStorageEmbeddedDBImpl(supportedClaimsImpl);
            
            KeystoreUtil keystore = new KeystoreUtil(keystorePath, keystorePassword);
//            privateKey = keystore.getPrivateKey(key,keyPassword);
            cert = keystore.getCertificate(key);
            domainname = properties.getProperty("domain");
            servletPath = properties.getProperty("servletPath");
            base64ImageFile = properties.getProperty("image-file");

        } catch (IOException e) {
            throw new ServletException(e);
        } catch (KeyStoreException e) {
            throw new ServletException(e);
        } catch (InstantiationException e) {
        	throw new ServletException(e);
		} catch (IllegalAccessException e) {
			throw new ServletException(e);
		} catch (ClassNotFoundException e) {
			throw new ServletException(e);
		}

    }


    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        HttpSession session = request.getSession(true);
        String username = getUsername(session);
        if (username == null) {
            dispatchUnauthenticatedRequest(request, response); // no username means invalid state . . .
            return;
        }

        System.out.println("Building backup file for " + username);
        EncryptedStore encryptedStore = null;
        RoamingStore store = new RoamingStore();

        List<String> cards = storage.getCards(username);
        for (String cardId : cards) {


            ManagedCard managedCard = storage.getCard(cardId);
            String tokenServiceEndpoint = "https://" + domainname + servletPath + "tokenservice";
            String mexEndpoint = "https://" + domainname + servletPath + "mex";

            InfoCard card = new InfoCard(); // no cert -> unsigned card
            card.setCardId("https://" + domainname + servletPath + "card/" + managedCard.getCardId(), 1);
            card.setCardName(managedCard.getCardName());
            card.setIssuer(tokenServiceEndpoint);

            XSDDateTime issued = new XSDDateTime();
            XSDDateTime expires = new XSDDateTime(525600);

            card.setTimeIssued(issued.getDateTime());
            card.setTimeExpires(expires.getDateTime());

            TokenServiceReference tsr = getTokenServiceReference(tokenServiceEndpoint, mexEndpoint, cert, username);
            ArrayList<TokenServiceReference>tokenServiceReferenceList = new ArrayList<TokenServiceReference>();
            tokenServiceReferenceList.add(tsr);
            card.setTokenServiceReference(tokenServiceReferenceList);

            {
	            SupportedToken token = new SupportedToken(WSConstants.SAML11_NAMESPACE);
	            ArrayList<SupportedToken> list = new ArrayList<SupportedToken>();
	            list.add(token);
	            SupportedTokenList tokenList = new SupportedTokenList(list);
	            card.setTokenList(tokenList);
            }
            
            SupportedClaimTypeList claimList = getSupportedClaimList();
            card.setClaimList(claimList);
            /*
            SupportedClaimList claimList = new SupportedClaimList();
            SupportedClaim given = new SupportedClaim("GivenName", Constants.IC_NAMESPACE_PREFIX + "givenname");
            SupportedClaim sur = new SupportedClaim("Surname", Constants.IC_NAMESPACE_PREFIX + "surname");
            SupportedClaim email = new SupportedClaim("EmailAddress", Constants.IC_NAMESPACE_PREFIX + "emailaddress");
            claimList.addSupportedClaim(given);
            claimList.addSupportedClaim(sur);
            claimList.addSupportedClaim(email);
            card.setClaimList(claimList);
            */
            
            try {
				card.setPrivacyPolicy(getPrivacyPolicyReference(domainname), privacyPolicyVersion);
			} catch (URISyntaxException e) {
				throw new ServletException("Error setting PrivacyNotice", e);
			}

			String issuerName = cert.getIssuerX500Principal().getName();
        	String hashSalt = "salt1234";
        	String timeLastUpdated = card.getTimeIssued();
        	String issuerId = card.getIssuer();
        	String backgroundColor = "16777215";
        	InformationCardMetaData informationCardMetaData = 
            	new InformationCardMetaData(card, false, null, hashSalt, timeLastUpdated, issuerId, issuerName, backgroundColor);
            SelfIssuedInformationCardPrivateData informationCardPrivateData = new SelfIssuedInformationCardPrivateData();
            RoamingInformationCard ric = new RoamingInformationCard(informationCardMetaData, informationCardPrivateData);
            store.addRoamingInformationCard(ric);

        }

        response.setContentType("application/informationCard-backup; charset=utf-8");
        ServletOutputStream out = response.getOutputStream();

        try {
            encryptedStore = new EncryptedStore(store, "password");
            encryptedStore.toStream(out);
        } catch (Exception e) {
            e.printStackTrace();
        }

        out.flush();
        out.close();

    }

    protected String getPrivacyPolicyReference(String domainname) {
        return "https://" + domainname + "/PrivacyPolicy.xml";
    }

    protected TokenServiceReference getTokenServiceReference(String tokenServiceEndpoint, String mexEndpoint, X509Certificate cert, String username) {
    	UserCredential usercredential = new UserCredential(UserCredential.USERNAME, username);
        TokenServiceReference tsr = new TokenServiceReference(tokenServiceEndpoint, mexEndpoint, cert, usercredential);
        return tsr;
    }

    protected SupportedClaimTypeList getSupportedClaimList() {
        List<DbSupportedClaim> supportedClaims = supportedClaimsImpl.dbSupportedClaims();

        ArrayList<SupportedClaim> cl = new ArrayList<SupportedClaim>();
        
        //PPID is breaking backup files
        //SupportedClaim supportedClaim = new SupportedClaim("PPID", org.xmldap.infocard.Constants.IC_NS_PRIVATEPERSONALIDENTIFIER);
        //claimList.addSupportedClaim(supportedClaim);
        for (DbSupportedClaim claim : supportedClaims) {
        	// TODO: support description. Axel
            SupportedClaim thisSupportedClaim = new SupportedClaim(claim.displayTags[0].displayTag, claim.uri, "A Description");
            cl.add(thisSupportedClaim);
        }

        SupportedClaimTypeList claimList = new SupportedClaimTypeList(cl);
        return claimList;
    }

    protected void dispatchUnauthenticatedRequest(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        RequestDispatcher dispatcher = request.getRequestDispatcher("/cardmanager/");
        dispatcher.forward(request, response);
    }

    protected String getUsername(HttpSession session) {
        String username = (String) session.getAttribute("username");
        return username;
    }

    /**
     * Get the card identifier from the GET request URL (i.e. http://sts.xmldap.org/card/<b>MY-CARD-IDENTIFIER</b>.crd
     *
     * @param request
     * @return a card identifier that can be used to retrieve the actual card object from the card store
     */
    protected static String extractCardIdFromRequest(HttpServletRequest request) {
        String url = request.getRequestURL().toString();
        return extractCardIdFromUrl(url);
    }

    /**
     * Get the card identifier from the GET request URL (i.e. http://sts.xmldap.org/card/<b>MY-CARD-IDENTIFIER</b>.crd
     *
     * @param url
     * @return a card identifier that can be used to retrieve the actual card object from the card store
     */

    protected static String extractCardIdFromUrl(String url) {
        int index = url.lastIndexOf("/");
        index++;
        String cardID = url.substring(index, url.length() - 4);
        return cardID;
    }

    /**
     * Gets the file referenced in servlet config and returns it's data as a Base64 string.
     * @return Base64 encoded image data (usaully a PNG)
     */
    protected String getImageFileEncodedAsBase64() {
        if (base64ImageFile != null) {
            try {
                return getImageFileEncodedAsBase64(base64ImageFile);
            } catch (Exception e) {
                System.err.println("CardServelet::getImageFileEncodedAsBase64: " + e.getMessage());
                // use the standard image, if an error occurs
                return null;
            }
        } else {
            System.out.println("Did not find the image file for the new card (" + base64ImageFile + ")");
            return null;
        }
    }

    /**
     * Gets the file referenced by path and returns it's data as a Base64 string.
     * @param imageFilePathString path to the file
     * @return Base64 encoded image data (usaully a PNG)
     */
    protected String getImageFileEncodedAsBase64(String imageFilePathString) {
        String encodedFile;
        encodedFile = Base64.encodeFromFile(imageFilePathString);
        return encodedFile;
    }
}
