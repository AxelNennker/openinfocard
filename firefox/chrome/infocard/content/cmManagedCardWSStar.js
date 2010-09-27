Components.utils.import("resource://infocard/cmCommon.jsm");

function getMex1(to, mexAddress) {
  var mexResponse;
  icDebug("getMex1: to="  + to  + " mexAddress=" + mexAddress);
  try {
    var messageIdInt = Math.floor(Math.random()*100000+1);
    var messageId = "urn:uuid:" + messageIdInt;
    var mex = "<s:Envelope " + 
      "xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" " + 
      "xmlns:a=\"http://www.w3.org/2005/08/addressing\">" + 
      "<s:Header>" + 
       "<a:Action s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</a:Action>" + 
       "<a:MessageID>" +   messageId  +  "</a:MessageID>" + 
       "<a:ReplyTo>" + 
        "<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>" + 
       "</a:ReplyTo>" + 
       "<a:To s:mustUnderstand=\"1\">" + to + "</a:To>" + 
      "</s:Header><s:Body/></s:Envelope>";

icDebug("getMex: mex request: " + mex);
icDebug("managedCard.carddata.managed.mex: " + mexAddress);

    var req = new XMLHttpRequest();
    req.open('POST', mexAddress, false);
    icDebug('mex xmlhttprequest open');
    req.setRequestHeader("Content-type", "application/soap+xml; charset=utf-8");
    req.setRequestHeader("Cache-Control", "no-cache");
    req.setRequestHeader("accept-language", "en-us");
    req.setRequestHeader("User-Agent", "xmldap infocard stack");
    icDebug('mex xmlhttprequest send');
    try {
      req.send(mex);
    }
    catch (e) {
      icDebug(e);
      alert("posting the MEX request failed." + e);
      return null;
    }
icDebug("getMex: mex POST request status="+req.status);
    if(req.status == 200) {
icDebug("getMex: mex POST request status 200");

        mexResponse = req.responseText; // bug 270553
        mexResponse = mexResponse.replace(/^<\?xml\s+version\s*=\s*(["'])[^\1]+\1[^?]*\?>/, ""); // bug 336551
        
icDebug("getMex POST 200: " + mexResponse);
        return mexResponse;
    } else {
      icDebug("getMex POST " + req.status + ": " + req.responseText);
      req.open('GET', mexAddress, false);
      icDebug('mex xmlhttprequest open');
      req.setRequestHeader("Content-type", "application/soap+xml; charset=utf-8");
      req.setRequestHeader("Cache-Control", "no-cache");
      req.setRequestHeader("accept-language", "en-us");
      req.setRequestHeader("User-Agent", "xmldap infocard stack");
      icDebug('mex GET xmlhttprequest send');
      try {
        req.send(null);
      }
      catch (ee) {
        icDebug(ee);
        alert("getting the MEX request failed." + ee);
        return null;
      }
      icDebug("getMex: mex GET request status="+req.status);
      if(req.status == 200) {
        icDebug("getMex: mex GET request status 200");
        mexResponse = req.responseText; // bug 270553
        mexResponse = mexResponse.replace(/^<\?xml\s+version\s*=\s*(["'])[^\1]+\1[^?]*\?>/, ""); // bug 336551
        icDebug("getMex: " + mexResponse);
        return mexResponse;
      } else {
        icDebug("getMex GET " + req.status + ": " + req.responseText);
      }
      return null;
    }
  } catch (getMex1Exception) {
    icDebug("getMex1 Exception: " + getMex1Exception);
  }
}

function getMexForCard(managedCard) {
  var to = xmlreplace(managedCard.carddata.managed.mex);
  var mexAddress = managedCard.carddata.managed.mex;
  var mexResponse = getMex1(to, mexAddress);
  return mexResponse;
}

function sendRST(sendRstParameter) {

  var tsEndpointAddressStr = sendRstParameter.tsEndpointAddressStr;
  var tsEndpointCertStr = sendRstParameter.tsEndpointCertStr;
  var usercredential = sendRstParameter.icUserCredential;
  var managedCard = sendRstParameter.managedCard;
  var requiredClaims = sendRstParameter.requiredClaims;
  var optionalClaims = sendRstParameter.optionalClaims;
  var tokenType = sendRstParameter.tokenType;
  var clientPseudonym = sendRstParameter.clientPseudonym;
  var relyingPartyURL = sendRstParameter.relyingPartyURL;
  var relyingPartyCertB64 = sendRstParameter.relyingPartyCertB64;
  var backingCard = sendRstParameter.backingCard;

  //    var issuerPolicy = sendRstParameter.issuerPolicy;
  //    if (issuerPolicy != null) {
  //      var to = xmlreplace(managedCard.carddata.managed.issuer);
  //      var mexAddress = issuerPolicy;
  //      var issuerMex = getMex1(to, mexAddress);
  //      icDebug("issuerMex=" + issuerMex);
  //    }
      
  //      var mexResponse = getMexForCard(managedCard);

    icDebug("sendRST::usercredential:" + usercredential);
    if (usercredential === undefined) {
      Components.utils.reportError("sendRST::usercredential === undefined");
      return null;
    }
    if (usercredential === null) {
      Components.utils.reportError("sendRST::usercredential === null");
      return null;
    }
    if (tsEndpointAddressStr === undefined) {
      Components.utils.reportError("sendRST::tsEndpointAddressStr === undefined");
      return null;
    }
    if (tsEndpointAddressStr === null) {
      Components.utils.reportError("sendRST::tsEndpointAddressStr === null");
      return null;
    }
    icDebug("sendRST::tsEndpointAddressStr:" + tsEndpointAddressStr);
    
    var rst = "<s:Envelope " + 
    "xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" " + 
    "xmlns:a=\"http://www.w3.org/2005/08/addressing\" " +
    "xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">" + 
    "<s:Header>" + 
         "<a:Action u:Id=\"_1\">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>" +
         "<a:To s:mustUnderstand=\"1\">" + xmlreplace(tsEndpointAddressStr) + "</a:To>" +
     "<o:Security s:mustUnderstand=\"1\" xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">"; 

  var ic = new Namespace("ic", "http://schemas.xmlsoap.org/ws/2005/05/identity");
  icDebug("usercredential.ic::UsernamePasswordCredential.toString()=" + usercredential.ic::UsernamePasswordCredential.toString() + ";");
  if (usercredential.ic::UsernamePasswordCredential.toString() !== "") {
        var hint = usercredential.ic::DisplayCredentialHint;
        icDebug("hint:" + hint);
//                var prompts = Components.classes["@mozilla.org/embedcomp/prompt-service;1"].getService(Components.interfaces.nsIPromptService);
        var prompts = Components.classes["@mozilla.org/network/default-auth-prompt;1"].getService(Components.interfaces.nsIAuthPrompt);
        var username = {value:usercredential.ic::UsernamePasswordCredential.ic::Username};
        var password = {value:""};
//                var check = {value: false};
        hint = hint + "("+ username.value + ")";
//                okorcancel = prompts.promptUsernameAndPassword(window, 'Card Authentication', hint, username, password, null, check);
        var okorcancel = prompts.promptUsernameAndPassword('Card Authentication', hint, tsEndpointAddressStr, prompts.SAVE_PASSWORD_PERMANENTLY, username, password);
        if (okorcancel === false) {
          return null;
        }
        var uid =  username.value;
        var pw =  password.value;

        var messageIdInt = Math.floor(Math.random()*100000+1);
        var messageId = "urn:uuid:" + messageIdInt;


        rst = rst + "<o:UsernameToken u:Id=\"" + messageId + "\"><o:Username>";

        rst = rst + xmlreplace(uid);

        rst = rst + "</o:Username><o:Password o:Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText\">";

        rst = rst + xmlreplace(pw);

        rst = rst + "</o:Password></o:UsernameToken>";
    }  else if (usercredential.ic::KerberosV5Credential.toString() !== "") {
      Components.utils.reportError("unimplemented user credential type: KerberosV5Credential");
    alert("unimplemented user credential type: KerberosV5Credential");
    return null;
    } else if (usercredential.ic::X509V3Credential.toString() !== "") {
//        var dsigNS = new Namespace("dsig", "http://www.w3.org/2000/09/xmldsig#");
//        var wsaNS = new Namespace("wsa", "http://www.w3.org/2005/08/addressing");
//        var mexNS = new Namespace("mex", "http://schemas.xmlsoap.org/ws/2004/09/mex");
//        var wssNS = new Namespace("wss", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
      Components.utils.reportError("unimplemented user credential type: X509V3Credential");
      alert("unimplemented user credential type: X509V3Credential");
      return null;
    } else if (usercredential.ic::SelfIssuedCredential.toString() !== "") {
      var hintSelfIssuedCredential = usercredential.ic::DisplayCredentialHint;
      icDebug("hint:" + hintSelfIssuedCredential);
      var usercredentialSelfIssuedCredential = usercredential.ic::SelfIssuedCredential.ic::PrivatePersonalIdentifier;
      icDebug("usercredential:" + usercredentialSelfIssuedCredential);
      icDebug("stsCert:" + managedCard.carddata.managed.stsCert);
      icDebug("tsEndpointCertStr:" + tsEndpointCertStr);
      icDebug("backingCard:" + backingCard);
      
      var serializedPolicy;
      try {
        var sicPolicy = {};
        sicPolicy.type = "selfAsserted";
        sicPolicy.card = backingCard.toString();
        sicPolicy.requiredClaims = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier";
        serializedPolicy = JSON.stringify(sicPolicy);
      } catch (jsonEx) {
        Components.utils.reportError("jsonEx: " + jsonEx);
        throw jsonEx;
      }
      var samlAssertion;
      try {
        samlAssertion = TokenIssuer.getToken(serializedPolicy);
      } catch (samlEx) {
        Components.utils.reportError("samlEx: " + samlEx);
        throw samlEx;
      }
      var securityTokenReference = "<o:SecurityTokenReference>";
      securityTokenReference = securityTokenReference + "<o:Embedded wsu:Id=\"token\">"
      securityTokenReference = securityTokenReference + samlAssertion;
      securityTokenReference = securityTokenReference + "</o:Embedded wsu:Id=\"token\">"
      securityTokenReference = securityTokenReference + "</o:SecurityTokenReference>";
      icDebug("securityTokenReference:" + securityTokenReference);
      
      rst = rst + securityTokenReference;
//      Components.utils.reportError("unimplemented user credential type: SelfIssuedCredential");
//      alert("unimplemented user credential type: SelfIssuedCredential");
//      return null;
    } else {
      Components.utils.reportError("undefined user credential type: " + usercredential.ic::SelfIssuedCredential);
      alert("undefined user credential type");
      return null;
    }         
            
    rst = rst + "</o:Security></s:Header>" +
    "<s:Body><wst:RequestSecurityToken Context=\"ProcessRequestSecurityToken\" " +
    "xmlns:wst=\"http://schemas.xmlsoap.org/ws/2005/02/trust\">";
    
    if (managedCard.carddata.managed.requireAppliesTo !== undefined) {
      var appliesTo = "<p:AppliesTo xmlns:p=\"http://schemas.xmlsoap.org/ws/2004/09/policy\"><a:EndpointReference>" + 
        "<a:Address>" + xmlreplace(relyingPartyURL) + "</a:Address>";
      if (relyingPartyCertB64 !== null) {
        appliesTo = appliesTo + 
            "<i:Identity xmlns:i=\"http://schemas.xmlsoap.org/ws/2006/02/addressingidentity\">" + 
            "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data>" +
      "<ds:X509Certificate>" + relyingPartyCertB64 + "</ds:X509Certificate>" +
      "</ds:X509Data></ds:KeyInfo></i:Identity>";
      }
      appliesTo = appliesTo + "</a:EndpointReference></p:AppliesTo>";
icDebug("requireAppliesTo" + appliesTo);
      rst = rst + appliesTo;
    }
        
    rst = rst + "<wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>" +
    "<wsid:InformationCardReference xmlns:wsid=\"http://schemas.xmlsoap.org/ws/2005/05/identity\">" +
    "<wsid:CardId>";
icDebug("cardid:"+ managedCard.id);
icDebug("cardid xmlreplaced:"+ xmlreplace(managedCard.id));
    rst = rst + xmlreplace(managedCard.id);

    rst = rst + "</wsid:CardId>";
    
    rst = rst + "<wsid:CardVersion>" + xmlreplace(managedCard.version) + "</wsid:CardVersion>" + "</wsid:InformationCardReference>";
        
     var claims = requiredClaims + " " + optionalClaims;
     var claimsArray = claims.split(/\s+/);
     var list = managedCard.carddata.managed.ic::SupportedClaimTypeList.ic::SupportedClaimType;
     var count=0;
     
     var requestedClaims = "";
//     if (claims.indexOf("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier") >= 0)  {
//       // PPID is not displayed to the user, so isClaimChecked returns null for ppid
//       requestedClaims = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier";
//     }
     
     for (var index = 0; index<list.length(); index++) {
       var supportedClaim = list[index];
       var uri = supportedClaim.@Uri;
       var claim = isClaimChecked("label_"+uri, uri);
       if (claim !== null) {
        var i = claim.indexOf("?");
        if (i > 0) { // dynamic claim. Uris starting with ? are not allowed
         icDebug("dynamic claim: " + claim);
         var staticPrefix = claim.substr(0,i);
         var foundit = false;
             for (var ii = 0; (ii<claimsArray.length) && (foundit === false); ii++) {
               var requestedUri = claimsArray[ii];
               if (requestedUri.indexOf(staticPrefix) === 0) {
                 icDebug("dynamic claim match: " + requestedUri);
                 requestedClaims = requestedClaims + "<wsid:ClaimType Uri=\"" + xmlreplace(requestedUri) + "\" xmlns:wsid=\"http://schemas.xmlsoap.org/ws/2005/05/identity\"/>";
                 foundit = true;
               }
             }
             if (foundit === false) {
              icDebug("dynamic claim: " + claim + " not found in " + claimsArray);
             }
        } else {
          icDebug("static claim: " + claim);
          requestedClaims = requestedClaims + "<wsid:ClaimType Uri=\"" + xmlreplace(uri) + "\" xmlns:wsid=\"http://schemas.xmlsoap.org/ws/2005/05/identity\"/>";
        }
        count++;
       } else {
        icDebug("claim is null: " + uri);
       }
   }
   if (count === 0) {
    icDebug("no claims were requested!");
   }
   rst = rst + "<wst:Claims>" + requestedClaims + "</wst:Claims>";
        
    rst = rst + "<wst:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</wst:KeyType>";
    
    if (requiredClaims.indexOf("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier") >= 0) {
        rst = rst + "<ClientPseudonym xmlns=\"http://schemas.xmlsoap.org/ws/2005/05/identity\"><PPID>" + xmlreplace(clientPseudonym) + "</PPID></ClientPseudonym>";
  }
    if (tokenType !== null) {
        rst = rst + "<wst:TokenType>" + xmlreplace(tokenType) + "</wst:TokenType>";
    }
    rst = rst + "<wsid:RequestDisplayToken xml:lang=\"en\" xmlns:wsid=\"http://schemas.xmlsoap.org/ws/2005/05/identity\"/>" +
    "</wst:RequestSecurityToken></s:Body></s:Envelope>";

    icDebug("sendRST: request: " + rst);
    var rstr;
    var rstReq = new XMLHttpRequest();
    rstReq.open('POST', tsEndpointAddressStr, false);
    rstReq.setRequestHeader("Content-type", "application/soap+xml; charset=utf-8");
    rstReq.setRequestHeader("Cache-Control", "no-cache");
    rstReq.setRequestHeader("accept-language", "en-us");
    rstReq.setRequestHeader("User-Agent", "xmldap infocard stack");
    try {
        rstReq.send(rst);
    } 
    catch (e) {
    icDebug("rstReq.send(rst) failed: " + e);
    alert("posting the request to get the security tokens failed. " + e);
      return null;              
    }
    
    var tokenToReturn = null;
    if(rstReq.status === 200) {
//      // should you replace the string voodoo below through something 
//        // more elaborate like E4X-handling then think of these two bugs
//        rstResponse = req.responseText; // bug 270553
//        rstResponse = mexResponse.replace(/^<\?xml\s+version\s*=\s*(["'])[^\1]+\1[^?]*\?>/, ""); // bug 336551

      icDebug("processManagedCard: request status 200");
    
      rstr = rstReq.responseText;
      icDebug("processManagedCard: RSTR:" + rstr);
    
      var j = rstReq.responseText.indexOf("RequestedSecurityToken");
      if (j<0) {
       alert("token server did not sent a RequestedSecurityToken.\n" + rstReq.responseText);
       return null;
      }
      var prefix;
      if (rstReq.responseText.charAt(j-1) === ':') {
          var start = rstReq.responseText.substring(0,j-1);
          var iii = start.lastIndexOf("<");
          if (iii<0) {
           alert("illegal XML\n" + start);
           return null;
          }
          prefix = start.substring(iii+1) + ":";
      } else {
        prefix = "";
      }    
      icDebug("prefix=" + prefix);
      var rest = rstReq.responseText.substring(j);
      icDebug("rest=" + rest);
      var l = rest.indexOf(">");
      rest = rest.substring(l+1);
      icDebug("Rest=" + rest);
      var k = rest.indexOf("</" + prefix + "RequestedSecurityToken");
      tokenToReturn = rest.substring(0,k);
        
      icDebug("RSTR: " + tokenToReturn);
    } else {
      icDebug("token request (" + tsEndpointAddressStr + ") failed. (" + rstReq.status +")\n" + rstReq.responseText);
      alert("token request (" + tsEndpointAddressStr + ") failed. (" + rstReq.status +")\n" + rstReq.responseText);
    }
    return tokenToReturn;
}

