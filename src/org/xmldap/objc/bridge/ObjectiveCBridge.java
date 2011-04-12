package org.xmldap.objc.bridge;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import nu.xom.Element;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.xmldap.exceptions.SerializationException;
import org.xmldap.infocard.SelfIssuedToken;
import org.xmldap.transport.SSLTransportUtil;
import org.xmldap.xmlenc.EncryptedData;

/**
 * This is a bag of utilities and an object "holder" collcted in a single class to make the callouts,
 * and state management, from ObjectiveC muche simpler.
 * <p/>
 * TODO: a "session" or "context" object might be the way to go, but let's just keep it simple for now.
 * <p/>
 * Interface can be found at org_xmldap_objc_bridge_ObjectiveCBridge.h
 *
 * @author igb
 */
public class ObjectiveCBridge {

    private String dn;
    private X509Certificate serverCertificate;
    private X509Certificate clientCertificate;
    private KeyPair pair;
    private SelfIssuedToken selfIssuedToken;
    private static final String MD5_WITH_RSAENCRYPTION = "MD5WithRSAEncryption";
    private static final String RSA = "RSA";

    public ObjectiveCBridge(String server) throws IOException {
        serverCertificate = getServerCertificate(server);
    }

    /**
     * I'm making a lot of assumptions here, but fuck it, it'll do for now.
     *
     * @param url
     * @return
     * @throws IOException
     */

    public static X509Certificate getServerCertificate(String url) throws IOException {
        Certificate[] certs = SSLTransportUtil.getServerCertificates(url);
        return (X509Certificate) certs[0];
    }


    public void createSelfIssuedToken() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA);
        pair = kpg.genKeyPair();

//        X509V3CertificateGenerator generator = new X509V3CertificateGenerator();
//
//
//        generator.setSerialNumber(BigInteger.valueOf(1));
//        generator.setIssuerDN(new X509Principal(dn));
//
//        // sit on a fence in a 48 hr window of validity
//        generator.setNotBefore(new Date(System.currentTimeMillis() - 1000 * 60 * 60 * 24));
//        generator.setNotAfter(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24));
//
//        generator.setSubjectDN(new X509Principal(dn));
//        generator.setPublicKey(pair.getPublic());
//        generator.setSignatureAlgorithm(MD5_WITH_RSAENCRYPTION);
//        clientCertificate = generator.generateX509Certificate(pair.getPrivate());

        RSAPublicKey signingKey = (RSAPublicKey)pair.getPublic();
        String signingAlgorithm = "SHA1withRSA";
        selfIssuedToken = new SelfIssuedToken(signingKey, pair.getPrivate(), signingAlgorithm);
        selfIssuedToken.setConfirmationMethodHOLDER_OF_KEY(serverCertificate);

    }


    public void addCardData(String cardData, String privatePersonalIdentifier) {
        selfIssuedToken.setPrivatePersonalIdentifier(privatePersonalIdentifier);
    }

    /**
     * Get the self-issued token in encryptred string.
     *
     * @return
     * @throws SerializationException
     */
    public String getEncryptedCardData() throws SerializationException {
        EncryptedData encryptedData = new EncryptedData(serverCertificate);
        Element securityToken = selfIssuedToken.serialize();
        encryptedData.setData(securityToken.toXML());
        return encryptedData.toXML();
    }

    /**
     * Get the DN used for the signing cert.
     *
     * @return the DN used for signing of the self asserted token.
     */
    public String getDn() {
        return dn;
    }

    /**
     * Set the DN used for the signing of the self asserted token.
     *
     * @param dn
     */
    public void setDn(String dn) {
        this.dn = dn;
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, SerializationException {
        ObjectiveCBridge bridge = new ObjectiveCBridge("https://xmldap.org");
        bridge.setDn("cn=Ian Brown");
        bridge.createSelfIssuedToken();
        bridge.addCardData("card", "ppid");
        System.out.println("bridge.getEncryptedCardData() = " +  bridge.getEncryptedCardData());

    }
}
