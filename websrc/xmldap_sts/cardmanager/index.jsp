<%@ page import="java.util.Iterator"%>
<%@ page import="org.xmldap.sts.db.ManagedCard"%>
<%@ page import="org.xmldap.sts.db.CardStorage"%>
<%@ page import="org.xmldap.sts.db.impl.CardStorageEmbeddedDBImpl"%>
<%@ page import="java.util.List"%>
<%@ page import="org.xmldap.exceptions.StorageException"%>
<%@ page import="org.xmldap.util.PropertiesManager"%>
<%@ page import="org.xmldap.sts.db.SupportedClaims"%>
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
	PropertiesManager properties = new PropertiesManager(PropertiesManager.SECURITY_TOKEN_SERVICE, getServletContext());
	String supportedClaimsClass = properties.getProperty("supportedClaimsClass");
	SupportedClaims supportedClaimsImpl = SupportedClaims.getInstance(supportedClaimsClass);
	CardStorage storage = new CardStorageEmbeddedDBImpl(supportedClaimsImpl);
	String servletPath = properties.getProperty("servletPath");
	String requiredClaims = properties.getProperty("requiredClaims"); 
	String optionalClaims = properties.getProperty("optionalClaims"); 
	String basePath = "";
	if ("https".equals(request.getScheme())) {
		if (443==request.getServerPort()) {
	    	basePath = "https://"+request.getServerName();
	    } else {
	    	basePath = "https://"+request.getServerName()+":"+request.getServerPort();
	    }
	 } else {
	 	if ("http".equals(request.getScheme())) {
	 		if (80==request.getServerPort()) {
	 			basePath = "http://"+request.getServerName();
	 		} else {
	 			basePath = "http://"+request.getServerName()+":"+request.getServerPort();
	 		}
	 	} else {
	 		basePath = request.getScheme()+"://"+request.getServerName()+":"+request.getServerPort();
	 	}
	 }
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

	<script  type="text/javascript">
		if (typeof(navigator.registerContentHandler) != 'undefined') {
<%
		out.println("\t\tnavigator.registerContentHandler(\"application/x-informationcard\", \"" + basePath + "/sts/?url=%s\", \"" + request.getServerName()+ " Information Card\");");
%>
		}
	</script>

    <style type="text/css">
    BODY {background: #FFFFFF;
         color:#000;
         font-family: verdana, arial, sans-serif;}

        h2 { color:#185F77;
         font-family: verdana, arial, sans-serif;}

        h4 { color:#000;
         font-family: verdana, arial, sans-serif;}

        .forminput{position:relative;size:300px;background-color: #ffffff;border: 1px solid #666666;}


        A {color: #657485; font-family:verdana, arial, sans-serif; text-decoration: none}
        A:hover {color: #657485; text-decoration: underline}

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


        #title {color: #FFF; font-weight:bold; font-size:250%; font-family:arial; text-decoration: none;
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

        #links A {color: #FFF; font-weight:bold; font-size:150%; font-family:arial; text-decoration: none}
        #links A:hover {color: #FFF; text-decoration: underline}

    </style>
    
</head>
<body>
<%

    String username = (String)session.getAttribute("username");

    if (username == null) {

        String uid = request.getParameter("uid");
        String password = request.getParameter("password");

        if ((uid != null) && (password != null))  {

            storage.startup();
            boolean isUser = storage.authenticate(uid,password);
            if ( isUser ) {
                username = uid;
                session.setAttribute("username",uid);

            } else {
                try {
                    storage.addAccount(uid,password);
                    session.setAttribute("username",uid);
                    username = uid;
                } catch (StorageException e) {
                    %>

                        <p style="font-style:bold">Authentication failed.</p>

                    <%

                }
            }

        }
    }

    if (username == null) {

%>

<p style="font-weight:bold">Please Login or Create an Account:</p>
<form action="" method="post">
    <table border="0" cellpadding="5">
    <tr><td>Username: </td><td><input type="text" name="uid" class="forminput"/> </td></tr>
    <tr><td>Password: </td><td><input type="password" name="password" class="forminput"/> </td></tr>
    </table>
                                                                          
    <input type="submit" value="Login or Create a New Account"/>                     
</form>



<%

    }  else {

%>

     <p style="font-weight:bold">Welcome, <%= escapeHtmlEntities(username) %></p>

<p>Here you can create and download managed cards.</p>
<p style="font-weight:bold">Your Cards:</p>

<table  border="0" cellpadding="5">
<%

    List cards = storage.getCards(username);
    Iterator iter = cards.iterator();
    while (iter.hasNext()) {

        String cardId = (String)iter.next();
        ManagedCard thisCard = storage.getCard(cardId);
        String cardImageStr = thisCard.getClaim("http://schemas.tlabs.de/2011/04/identity/claims/cardfrontimage");
        if (cardImageStr == null) {
            cardImageStr = "../img/click_me_card.png";
        }
        String href = "/" + servletPath + "/card/" + thisCard.getCardId() + ".crd";
        out.println("<tr><td><a href=\"" + href + "\">" + thisCard.getCardName() + "</a></td><td>");
        out.println("<form method='post' action='' id='form" + thisCard.getCardId() + "' enctype='application/x-www-form-urlencoded'>");
        %>
		<p>
		<img width="72" height="37"
		     <%
             out.println(" alt=\"" + cardId + "\"");
             out.println(" src=\"" + cardImageStr + "\"");
             out.println(" onclick='var pf = document.getElementById(\"form" + thisCard.getCardId() + "\"); pf.submit();'/>");
		     %>
        <object type="application/x-informationcard" name="xmlToken">
		<%
		    out.println("<param name=\"issuer\" value=\"" + basePath + href + "\"/>");
		%>
		    <param name="tokenType" value="urn:oasis:names:tc:IC:1.0:managedcard"/>
		
            </object>
		</p>
		</form>
        <%
        out.println("</td></tr>");

    }

    String backupfile = "/" + servletPath + "/backup/" + escapeHtmlEntities(username) + ".crds";


%>

</table>


<p style="font-style:bold">Operations:</p>
<p>
<a href="<%= backupfile %>">Download all your cards as a Cardspace Backup file</a></p>
<p>
<a href="./createcard.jsp">Create a new card backed by your username and password</a>
</p>


<%
    }

%>

</body>
</html>
