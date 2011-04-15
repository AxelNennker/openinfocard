<%@ page import="java.util.List"%>
<%@ page import="java.util.Locale"%>
<%@ page import="java.util.Iterator"%>
<%@ page import="java.io.InputStream"%>
<%@ page import="org.xmldap.sts.db.ManagedCard"%>
<%@ page import="org.xmldap.sts.db.CardStorage"%>
<%@ page import="org.xmldap.sts.db.DbSupportedClaim"%>
<%@ page import="org.xmldap.sts.db.impl.CardStorageEmbeddedDBImpl"%>
<%@ page import="org.xmldap.util.PropertiesManager"%>
<%@ page import="org.xmldap.sts.db.SupportedClaims"%>
<%@ page import="org.xmldap.util.XSDDateTime"%>
<%@ page import="org.xmldap.util.Base64"%>
<%@ page import="org.apache.commons.fileupload.servlet.ServletFileUpload"%>
<%@ page import="org.apache.commons.fileupload.disk.DiskFileItemFactory"%>
<%@ page import="org.apache.commons.fileupload.FileUploadException"%>
<%@ page import="org.apache.commons.fileupload.FileItem"%>

<%

	PropertiesManager properties = new PropertiesManager(PropertiesManager.SECURITY_TOKEN_SERVICE, getServletContext());
	String supportedClaimsClass = properties.getProperty("supportedClaimsClass");
	SupportedClaims supportedClaimsImpl = SupportedClaims.getInstance(supportedClaimsClass);
	CardStorage storage = new CardStorageEmbeddedDBImpl(supportedClaimsImpl);
    String servletPath = properties.getProperty("servletPath");
	String AcceptHeaderValue = request.getHeader("Accept");
	if ((AcceptHeaderValue != null) && (AcceptHeaderValue.indexOf("application/xhtml+xml") >= 0)) {
		response.setContentType("application/xhtml+xml");
	}

%>
<!DOCTYPE HTML><html>
<!--
<!DOCTYPE html 
     PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
     "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
-->
<head>
    <title>XMLDAP Card Manager</title>


    <style>
    BODY {background: #FFFFFF;
         color:#000;
         font-family: verdana, arial, sans-serif;}

        h2 { color:#185F77;
         font-family: verdana, arial, sans-serif;}

        h4 { color:#000;
         font-family: verdana, arial, sans-serif;}

        .forminput{position:relative;width:300;background-color: #ffffff;border: 1px solid #666666;}


        A {color: #657485; font:verdana, arial, sans-serif; text-decoration: none}
        A:hover {color: #657485; text-decoration: underline}

        .container {
           background-color: #FFFFFF;
           padding: 10px;
           margin: 10px;
           font-family:verdana, arial, sans-serif;
            position:relative;
              left:0;
              top:25;
            width: 95%;
           }


        #title {color: #FFF; font:bold 250% arial; text-decoration: none;
            position:relative;
              left:10;
              top:42;
        }

        #links {
            position:relative;
              left:-5;
              top:11;
        text-align: right;
        }

        #links A {color: #FFF; font:bold 150% verdana, arial, sans-serif; text-decoration: none}
        #links A:hover {color: #FFF; text-decoration: underline}

    </style>
</head>
<body>
<%


    String username = (String)session.getAttribute("username");

    if (username == null) {


%>

    <script type="text/javascript">
        document.location = <%=servletPath%>+"/cardmanager/";
    </script>


<%
    }  else {
        if ("GET".equals(request.getMethod())) {

%>
<p style="font-weight:bold">Create a card</p><br/><br/>
<form action="./createcard.jsp" method="post" enctype="multipart/form-data">
    <input type="hidden" name="action" value="createcard"/>
    <table>
    <tr><td>Card Name:</td><td><input type="text" name="cardName" class="forminput"/></td></tr>
<%
		Locale clientLocale = request.getLocale();
		List dbSupportedClaims = supportedClaimsImpl.dbSupportedClaims();
		for (int i=0; i<dbSupportedClaims.size(); i++) {
		 DbSupportedClaim claim = (DbSupportedClaim)dbSupportedClaims.get(i);
		 String key = claim.columnName;
		 String displayTag = claim.getDisplayTag(clientLocale);
		 String columnType = claim.columnType;
         String uri = claim.uri;
		 String inputType = "text";
		 if (columnType.indexOf("varChar(") > -1) {
		  inputType = "text";
		 } else if (uri.indexOf("/file/") > -1) {
		  inputType = "file";
		 }
		 out.println("<tr><td>" + displayTag + ":</td><td><input type=\"" + inputType + "\" name=\"" + key + "\" class=\"forminput\"/></td></tr>");
		}
        if (storage.getVersion() > 1) {
            System.out.println("createcard.jsp: dbVersion=" + storage.getVersion());
            out.println("<tr><td>" + "RequireAppliesTo" + ":</td><td><input type=\"checkbox\" name=\"" + "RequireAppliesTo" + "\" class=\"forminput\"/></td></tr>");
            out.println("<tr><td>" + "RequireStrongRecipientIdentity" + ":</td><td><input type=\"checkbox\" name=\"" + "RequireStrongRecipientIdentity" + "\" class=\"forminput\"/></td></tr>");
        }
        if (storage.getVersion() > 2) {
            out.println("<tr><td>" + "Card Front Image" + ":</td><td><input type=\"file\" name=\"" + "cardfrontimage" + "\" class=\"forminput\"/></td></tr>");
            out.println("<tr><td>Card Front HTML:</td><td><textarea cols=\"35\" rows=\"4\" name=\"cardfronthtml\"></textarea></td></tr>");

            out.println("<tr><td>" + "Card Back Image" + ":</td><td><input type=\"file\" name=\"" + "cardbackimage" + "\" class=\"forminput\"/></td></tr>");
            out.println("<tr><td>Card Back HTML:</td><td><textarea cols=\"35\" rows=\"4\" name=\"cardbackhtml\"></textarea></td></tr>");
        }
%>
    <tr><td colspan="2"><br/><input type="submit" value="Create a new card"/></td></tr>
    </table>
</form>

<%
    } else {

        boolean isMultipart = ServletFileUpload.isMultipartContent(request);

        if ( ! isMultipart ) {
            out.println("Invalid form posting - not multipart</body></html>");
            out.flush();
            return;
        }
        
        DiskFileItemFactory factory = new DiskFileItemFactory();
        factory.setSizeThreshold(500000);
        ServletFileUpload upload = new ServletFileUpload(factory);
        upload.setSizeMax(1000000);

        storage.startup();

        ManagedCard card = new ManagedCard();

        try {
            List<FileItem> items = upload.parseRequest(request);
            Iterator<FileItem> iter = items.iterator();
            while (iter.hasNext()) {
                FileItem item = (FileItem) iter.next();

                if (item.isFormField()) {
                    String name = item.getFieldName();
                    System.out.println("createcard: fieldname " + name);
                    if ("cardName".equals(name)) {
                        String cardName = item.getString();
                        if (cardName != null) {
                            cardName = cardName.trim();
                            if (!"".equals(cardName)) {
                                card.setCardName(cardName);
                            }
                        }
                    } else if ("RequireAppliesTo".equals(name)) {
                        String audit = item.getString();
                        if (audit != null) {
                            audit = audit.trim();
                            if (!"".equals(audit)) {
                                card.setRequireAppliesTo(true);
                            }
                        }
                    } else if ("RequireStrongRecipientIdentity".equals(name)) {
                        String strongCrypto = item.getString();
                        if (strongCrypto != null) {
                            strongCrypto = strongCrypto.trim();
                            if (!"".equals(strongCrypto)) {
                                card.setRequireStrongRecipientIdentity(true);
                            }
                        }
                    } else if ("cardfronthtml".equals(name)) {
                        String cardfronthtml = item.getString();
                        if (cardfronthtml != null) {
                            cardfronthtml = card.getFrontHtml();
                            if (!"".equals(cardfronthtml)) {
                                card.setFrontHtml(cardfronthtml);
                            }
                        }
                    } else if ("cardbackhtml".equals(name)) {
                        String cardbackhtml = item.getString();
                        if (cardbackhtml != null) {
                            cardbackhtml = card.getBackHtml();
                            if (!"".equals(cardbackhtml)) {
                                card.setBackHtml(cardbackhtml);
                            }
                        }
                    } else {
                        List dbSupportedClaims = supportedClaimsImpl.dbSupportedClaims();
                        boolean found = false;
                        for (int i=0; i<dbSupportedClaims.size(); i++) {
                            DbSupportedClaim claim = (DbSupportedClaim)dbSupportedClaims.get(i);
                            String key = claim.columnName;
                            if (key.equals(name)) {
                                found = true;
                                String value = item.getString();
                                if (value != null) {
                                    value = value.trim();
                                    if (!"".equals(value)) {
                                        card.setClaim(claim.uri, value);
                                    }
                                }                            
                            }
                        }
                        if (!found)  {
                            System.out.println("createcard: unknown field " + name);
                        }
                    }
                } else {
                  try {
                    String name = item.getFieldName();
                    System.out.println("createcard: Fieldname " + name);
                    
                    InputStream in = item.getInputStream();
                    int size = (int)item.getSize();
                    String contentType = item.getContentType();
                    System.out.println("createcard: file field " + name + " size=" + String.valueOf(size) +
                     " content-type=" + contentType);
                    if (size > 0) {
                        if (size > 32672) {
                            System.out.println("createcard: the file " + name + " is too big! size=" + size);
                        }
                        if (size <= 0) {
                            size = 32672;
                        }
                        byte buffer[] = new byte[size];
                        int count = 1;
                        int offset = 0;
                        int length = buffer.length;
                        while ((count > 0) && (length > 0)){
                            count = in.read(buffer, offset, length);
                            if (count > 0) {
                                offset += count;
                                length -= count;
                            }
                            if (count == 0) break;
                        }
                        String value = "data:" + contentType + ";base64," + Base64.encodeBytesNoBreaks(buffer);
                        if ("cardfrontimage".equals(name)) {
                            card.setCardfrontimage(value);
                        } else if ("cardbackimage".equals(name)) {
                            card.setCardbackimage(value);
                        } else {
                            System.out.println("createcard: unknown file field " + name);
                        }
                      }
                    } catch(Exception e) {
                        System.err.println("createcard exception: " + e.getMessage()); // continue
                    }
                 }
            }


        } catch (FileUploadException e) {
            out.println("There was an error receiving your backup file. Exception: " + e.getMessage());
            out.flush();
            return;
        }
        
	    String timeissued = new XSDDateTime().getDateTime();
	    card.setTimeIssued(timeissued);
        storage.addCard(username, card);

        out.println("<script type=\"text/javascript\">document.location = \"/" + servletPath + "/cardmanager/\";</script>");

    }

}
%>
</body>
</html>