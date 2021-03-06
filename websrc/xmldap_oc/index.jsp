<%@ page session="true" %>
<%!

	String escapeHtmlEntities(String html) {
		StringBuffer result = new StringBuffer();
		for (int i = 0; i < html.length(); i++) {
			char ch = html.charAt(i);
			if (ch == '<') {
				result.append("&lt;");
			} else if (ch == '>') {
				result.append("&gt;");
			} else if (ch == '\"') {
				result.append("&quot;");
			} else if (ch == '\'') {
				result.append("&#039;");
			} else if (ch == '&') {
				result.append("&amp;");
			} else {
				result.append(ch);
			}
		}
		return result.toString();
	}
%>
<%
 org.xmldap.util.PropertiesManager properties = new org.xmldap.util.PropertiesManager(org.xmldap.util.PropertiesManager.RELYING_PARTY, config.getServletContext());
 String requiredClaims = properties.getProperty("requiredClaims"); 
 String optionalClaims = properties.getProperty("optionalClaims"); 
 String tokentype = properties.getProperty("tokentype"); 
 String returnTo = properties.getProperty("returnTo"); 
 String protocol = properties.getProperty("protocol"); 
 String OpenIDAuthParameters = properties.getProperty("OpenIDAuthParameters"); 
 String issuer = properties.getProperty("issuer"); 

 String queryString = request.getQueryString();
 if (queryString != null) {
 	if (queryString.indexOf("privacy") == 0) {
	 System.out.println("queryString.indexOf(\"privacy\") = " + queryString.indexOf("privacy"));
	 String contentType = request.getContentType();
	 System.out.println("privacyStatement request content-Type: " + contentType);
	 if (contentType == null) {
		 contentType = "text/plain";
	 } else if ("*/*".equals(contentType)) {
		 contentType = "text/plain";
	 }
	 String privaceStatement = properties.getProperty("privacyStatement." + contentType); 
	 if (privaceStatement == null) {
		 privaceStatement = properties.getProperty("privacyStatement.text/plain"); 
		 if (privaceStatement == null) {
			 response.sendError(500, "could not find privacy statement of content type (" + contentType + ")");
			 return;
		 } else {
			 contentType = "text/plain";
		 }
	 }
	 response.setContentType(contentType);
	 System.out.println("reading : " + privaceStatement);
	 java.io.InputStream fis = getServletContext().getResourceAsStream(privaceStatement);
	 if (fis == null) {
	 	System.out.println("could not find resource: " + privaceStatement);
	 	// TODO send HTTP not found
	 	return;
	 }
//	 java.io.FileInputStream fis = new java.io.FileInputStream(privaceStatement);
	 java.io.BufferedReader ins = new java.io.BufferedReader(new java.io.InputStreamReader(fis));
	 try {
		 String line = ins.readLine();
			while (line != null) {
				out.println(line);
				line = ins.readLine();
			}
		} catch (java.io.IOException e) {
			throw new ServletException(e);
		}
		finally {
			fis.close();
			ins.close();
		}
   } else  if (queryString.indexOf("xmldap_rp.xrds") == 0) {
	 System.out.println("queryString.indexOf(\"xmldap_rp.xrds\") = " + queryString.indexOf("xmldap_rp.xrds"));
	 String xrds = properties.getProperty("xrds"); 
	 if (xrds != null) {
		 response.setContentType("application/xml+xrds");
		 System.out.println("reading xrds : " + xrds);
		 java.io.InputStream fis = getServletContext().getResourceAsStream(xrds);
	//	 java.io.FileInputStream fis = new java.io.FileInputStream(xrds);
		 java.io.BufferedReader ins = new java.io.BufferedReader(new java.io.InputStreamReader(fis));
		 try {
			 String line = ins.readLine();
				while (line != null) {
					out.println(line);
					line = ins.readLine();
				}
			} catch (java.io.IOException e) {
				throw new ServletException(e);
			}
			finally {
				fis.close();
				ins.close();
			}
	} else {
		System.out.println("ERROR: resource not found: " + xrds);
		// TODO return HTTP not found
	}
  } else  if (queryString.indexOf("login.xml") == 0) {
		 System.out.println("queryString.indexOf(\"login.xml\") = " + queryString.indexOf("login.xml"));

		 response.setContentType("application/xml");
		 out.println("<object type=\"application/x-informationcard\" name=\"xmlToken\">");
		 out.println("<param name=\"protocol\" value=\"" + protocol + "\"/>");
		 out.println("<param name=\"OpenIDAuthParameters\" value=\"" + OpenIDAuthParameters + "\"/>");
   		 out.print("<param name=\"privacyUrl\" value=\""); out.print(request.getRequestURL()); out.println("?privacy.txt\"/>");
		 out.println("<param name=\"privacyVersion\" value=\"1\"/>");
    	 out.println("\t<param name=\"tokenType\" value=\"" + tokentype + "\"/>");
		 out.println("</object>");

	  
  } else {
		if (request.getParameter("logout")!=null)
		{
		    session.removeAttribute("openid");
		    session.removeAttribute("openid-claimed");
		} else {
			System.out.println("unhandled querystring: " + queryString);
		}
  }
 } else {
		String userAgent = request.getHeader("user-agent");
		String cardSelectorName = request.getHeader("X-ID-Selector");
		boolean isOpenInfocardSelector = false;
		if (cardSelectorName != null) {
			isOpenInfocardSelector = (cardSelectorName.indexOf("openinfocard") != -1);
		}
	out.println("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">");
%>
<%
 String linkElement = "<link rel=\"xrds.metadata\" href=\"" + request.getServletPath() + "?xmldap_rp.xrds" + "\"/>";
 String metaElement = "<meta http-equiv=\"X-XRDS-Location\" content=\"" + request.getRequestURL() + "?xmldap_rp.xrds" + "\"/>";
%>

<%@page import="java.net.URLEncoder"%><html xmlns="http://www.w3.org/1999/xhtml">
<head>
	<title>XMLDAP OpenID Consumer</title>
	<%= metaElement %>
    
    <style type="text/css">
    BODY {background: #FFF url(./img/banner.png) repeat-x;
         color:#000;
         font-family: verdana, arial, sans-serif;}

        h2 { color:#185F77;
         font-family: verdana, arial, sans-serif;}

        h4 { color:#000;
         font-family: verdana, arial, sans-serif;}

        .forminput{position:relative;width:300px;background-color: #ffffff;border: 1px solid #666666;}


        A {color: #657485; font-family:verdana, arial, sans-serif; text-decoration: none}
        A:hover {color: #657485; text-decoration: underline}

		.droparea:-moz-drag-over {
		  border: 1px solid black;
		}

        .container {
           background-color: #FFFFFF;
           padding: 10px;
           margin: 10px;
           font-family:verdana, arial, sans-serif;
            position:relative;
              left:0px;
              top:25px;
            width: 95%;
           }


        #title {color: #FFF; font:bold 250% arial; text-decoration: none;
            position:relative;
              left:10px;
              top:42px;
        }

        #links {
            position:relative;
              left:-5px;
              top:11px;
        text-align: right;
        }

        #links A {color: #FFF; font-weight:bold; font-family:verdana, arial, sans-serif; text-decoration: none}
        #links A:hover {color: #FFF; text-decoration: underline}

    </style>
    
</head>
<body>
	<div id="title">selector based openid consumer</div>
	<div id="links">
	<a href="../">resources</a>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
	<a href="http://ignisvulpis.blogspot.com">ignisvulpis.blogspot.com</a>
	</div>


	<div>   <br/>
	<div class="container" id="relying_party">

<%
	if (session.getAttribute("openid") != null) {
%>
		<div>Logged in as <%= session.getAttribute("openid") %></div>
		<a href="?logout=true">Log out</a>
<%	
	}
%>

<h2>Login with an openid InfoCard</h2>
    <table border="0">
        <tr>
            <td>
<% if (request.getHeader("User-Agent").contains("iPhone") || 
		request.getHeader("User-Agent").contains("iPod")) { 
      String policy = "<object type=\"application/x-informationcard\" name=\"xmlToken\">" +
      	"<param name=\"privacyUrl\" value=\"" + request.getRequestURL() + "?privacy.txt\"/>" +
      	"<param name=\"requiredClaims\" value=\"" + requiredClaims + "\"/>" +
      	"<param name=\"optionalClaims\" value=\"" + optionalClaims + "\"/>" +
      	"<param name=\"tokenType\" value=\"" + tokentype + "\"/>" +
      	"<param name=\"privacyVersion\" value=\"1\"/>" +
      	"</object>";
      	String encodedPolicy = URLEncoder.encode(policy, "UTF-8");
      String iPhoneLink = "<a href=\"icard-https://xmldap.org/relyingparty/infocard?_policy=" + 
      	encodedPolicy +
      	"\">Click here to send i-card</a>";
      out.println(iPhoneLink);
      %>
<% } else { %>

<%
	out.println("<form method='post' action='" + returnTo + "' id='infocard' enctype='application/x-www-form-urlencoded'>");
	out.println("<p>");
	if (isOpenInfocardSelector) {
%>		
<!--  ondragover="return false" dragenter="return false"  -->
<img id="icDropTarget" class="droparea" src="./img/card_off.png" alt=""
     onmouseover="this.src='./img/card_on.png';"
     onmouseout="this.src='./img/card_off.png';"
     onclick='var pf = document.getElementById("infocard"); pf.submit();'/>
<%
	} else {
%>
<img src="./img/card_off.png" alt=""
     onmouseover="this.src='./img/card_on.png';"
     onmouseout="this.src='./img/card_off.png';"
     onclick='var pf = document.getElementById("infocard"); pf.submit();'/>
<%
	}
%>

    <object type="application/x-informationcard" name="xmlToken">
<%
		out.println("\t<param name=\"privacyUrl\" value=\"" + request.getRequestURL() + "?privacy.txt\"/>");
		out.println("<param name=\"protocol\" value=\"" + protocol + "\"/>");
    	out.println("\t<param name=\"tokenType\" value=\"" + tokentype + "\"/>");
    	out.println("\t<param name=\"issuer\" value=\"" + issuer + "\"/>");
		out.println("<param name=\"OpenIDAuthParameters\" value=\"" + OpenIDAuthParameters + "\"/>");

%>
    			  <param name="privacyVersion" value="1"/>
    			  <param name="icDropTargetId" value="icDropTarget"/>
    </object>
<%
	out.println("</p>");
	out.println("</form>");
%>
                    <br/>Click on the image above to login with your openID selector.<br/>
<% } %>
                    <br/><a href="/sts/cardmanager/">Click here to create a managed card.</a>

            </td>
        </tr>
    </table>

<%
if (userAgent != null) {
	out.println("<p style=\"font-size:xx-small\">Your user agent is: " + escapeHtmlEntities(userAgent) + "</p>");
}
if (cardSelectorName != null) {
	out.println("<p style=\"font-size:xx-small\">Your ID selector is: " + escapeHtmlEntities(cardSelectorName) + "</p>");
}
%>
    </div>
    </div>

</body>
</html>
<%
} 
%>

