
function mwDebug(msg) {
    var debug = Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService);
    debug.logStringMessage("mWallet: " + msg);
}

function cancel(){
  mwDebug("cancel");
    var doc = window.document;
    var event = doc.createEvent("Events");
    event.initEvent("CancelIdentitySelector", true, true);
    window.dispatchEvent(event);

     if ((!(window.arguments == undefined)) && (window.arguments.length > null)) {
       try {
         window.arguments[1](null);
       } catch (e) {
         Components.utils.reportError("mWallet.cancel: " + e);
       }
  }
    window.close();
}

function getPolicy(){
  var policy = null;
  if ((!(window.arguments == undefined)) && (window.arguments.length > null)) {
      policy = window.arguments[0];
  }
  return policy;
}

function isPhoneAvailable(){
  var msg;
  var label = document.getElementById("notify");
  var stringsBundle = document.getElementById("string-bundle");

  try {
    var phoneAvailable = TokenIssuer.isPhoneAvailable();
    if (phoneAvailable === true) {
      TokenIssuer.resetWalletException();
      if (label) {
        msg = "Thank you";
        if (stringsBundle) {
          var text = stringsBundle.getString('thankyou');
          if (text) {
            msg = text;
          }
        }
        label.setAttribute("value", msg );
      }
      return true;
    }
  } catch (ee) {
    mwDebug("isPhoneAvailable exception=" + ee );
    throw ee;
  } 
  var exception = TokenIssuer.getWalletException();
  if (exception) {
    Components.utils.reportError("mWallet.isPhoneAvailable: " + exception);
    if (label) {
      var str = "" + exception + "";
      if (str.indexOf("WalletIsLockedException") >= 0) {
        var msg = "Please unlock the wallet on your phone";
        if (stringsBundle) {
          var text = stringsBundle.getString('walletislocked');
          if (text) {
            msg = text;
          }
          label.setAttribute("value", msg );
        }
      }
      
    }
  } else {
    if (label) {
      msg = "Please put your NFC-phone on the NFC-reader!";
      if (stringsBundle) {
        var text = stringsBundle.getString('pleaseputyournfcphoneonthereader');
        if (text) {
          msg = text;
        }
      }
      label.setAttribute("value", msg );
    }
  }
  return false;
}

function mWalletUnload(){
  mwDebug("mWalletUnload start. href=" + window.document.location.href );
  
  try {
    TokenIssuer.endCardSelection();
  } catch (e) {
    Components.utils.reportError("mWalletUnload:endCardSelection " + e);
  }
  try {
    TokenIssuer.phoneFini();
  } catch (e) {
    Components.utils.reportError("mWalletUnload:phoneFini " + e);
  }
  try {
    TokenIssuer.finalize();
  } catch (e) {
    Components.utils.reportError("mWalletUnload:finalize " + e);
  }
}

function pollForPhoneAvailableCallback(policy){
  var card = null;

  var phoneAvailable = isPhoneAvailable();

  if (phoneAvailable === true) {
    if (policy.hasOwnProperty("timeoutId")) {
      window.clearInterval(policy["timeoutId"]);
      delete policy.timeoutId;
    }

    try {
//    TokenIssuer.beginCardSelection();
      try {
        // remove certs for now FIXME
        if (policy.hasOwnProperty("cert")) {
          delete policy.cert;
        }
        if (policy.hasOwnProperty("chainLength")) {
          for (var i=0; i<policy.chainLength;i++) {
            delete policy["certChain"+i];
          }
          delete policy.chainLength;
        }
      } catch(ee) {
        // ignore missing certs
      }
      // FIXME
      // http://schemas.t-labs.de/ws/2010/10/identity/claims/shopname?v=T-Labs+Computershop
      if (policy.hasOwnProperty("optionalClaims")) {
        var optionalClaims = policy.optionalClaims;
        var i = optionalClaims.indexOf("http://schemas.t-labs.de/ws/2010/10/identity/claims/shopname?v=");
        if (i>=0) {
          var shopname = optionalClaims.substring(i+ ("http://schemas.t-labs.de/ws/2010/10/identity/claims/shopname?v=".length));
          shopname = shopname.replace(/\s+/g,' ');
          var j = shopname.indexOf(" ");
          if (j > 0) {
            shopname = shopname.substring(0,j);
          }
          policy.shopname = shopname.replace('+',' '); // uri decode
        }
      }
      
      // http://schemas.t-labs.de/ws/2010/10/identity/claims/price?v=500+Euro
      if (policy.hasOwnProperty("optionalClaims")) {
        var optionalClaims = policy.optionalClaims;
        var i = optionalClaims.indexOf("http://schemas.t-labs.de/ws/2010/10/identity/claims/price?v=");
        if (i>=0) {
          var price = optionalClaims.substring(i + ("http://schemas.t-labs.de/ws/2010/10/identity/claims/price?v=".length));
          price = price.replace(/\s+/g,' ');
          var j = price.indexOf(" ");
          if (j > 0) {
            price = price.substring(0,j);
          }
          mwDebug("pollForPhoneAvailableCallback price=" + price );
          policy.price = price.replace('+',' '); // uri decode
          mwDebug("pollForPhoneAvailableCallback policy.price=" + policy.price );
        }
      }
      policy.timestamp = (new Date()).toLocaleString();
      var serializedPolicy = JSON.stringify(policy);
      TokenIssuer.startCardSelection(serializedPolicy);
    } catch (e) {
      Components.utils.reportError("TokenIssuer.startCardSelection " + e);
      return;
    }
    policy["timeoutId"] = window.setInterval(function(){pollForSelectedCardCallback(policy);}, 1000, true);
  }
}

function _card2token(policy, card) {
  var claimValueList = "";
  var cardname;
  var givenname;
  var surname;
  var emailaddress;
  var modulus;
  var cardXml;
  var domain;
  var icon;
  var number;

  mwDebug("_card2token: card=" + card);
//  mWallet: _card2token: card=
//    <Card name="Postbank VISA Card" issuer="Postbank" domain="Payment" type="Visa" icon="http://212.201.108.49/wallet/card_pb_visa.jpg"> <Attribute name="number" type="4" scope="0">2345678 </Attribute> 
//     <Attribute name="validFrom" type="4" scope="0">08.2008 </Attribute> 
//     <Attribute name="validTo" type="4" scope="0">08.2012 </Attribute> 
//    </Card>
  var cardXml = null;
  try {
//    var serializer = Components.classes['@mozilla.org/xmlextras/xmlserializer;1'].createInstance(Components.interfaces.nsIDOMSerializer);
//    var serializedCard = serializer.serializeToString("" + card);
    cardXml = new XML("" + card);
  } catch(e) {
    mwDebug("_card2token: exception=" + e);
  }
  if (cardXml) {
    try {
      mwDebug("_card2token: typeof(cardXml)=" + typeof(cardXml));
      mwDebug("_card2token: cardXml=" + cardXml.toXMLString());
      mwDebug("_card2token: cardXml.Attribute.length()=" + cardXml.Attribute.length());
      for (var i = 0; i < cardXml.Attribute.length(); i++) {
        var attr = cardXml.Attribute[i];
        mwDebug(attr.toString());
        var name = attr.@name.toString();
        var value = attr.child(0);
        mwDebug("_card2token: name=" + name + " value=" + value);
        
        if (name === "email") {
          emailaddress = value;
          claimValueList += "<ic:ClaimValue Uri=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress\">" +
          "<ic:Value>" + value + "</ic:Value>" + 
          "</ic:ClaimValue>";
        } else if (name === "name") {
          cardname = value;
          var x = cardname.split(' ');
          givenname = x[0];
          "<ic:ClaimValue Uri=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname\">" +
          "<ic:Value>" + givenname + "</ic:Value>" + 
          "</ic:ClaimValue>";
          surname = x[1];
          claimValueList += "<ic:ClaimValue Uri=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname\">" +
          "<ic:Value>" + surname + "</ic:Value>" + 
          "</ic:ClaimValue>";
        } else if (name === "surname") {
          surname = value;
          claimValueList += "<ic:ClaimValue Uri=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname\">" +
          "<ic:Value>" + value + "</ic:Value>" + 
          "</ic:ClaimValue>";
        } else if (name === "givenname") {
          givenname = value;
          claimValueList += "<ic:ClaimValue Uri=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname\">" +
          "<ic:Value>" + value + "</ic:Value>" + 
          "</ic:ClaimValue>";
        } else if (name === "Modulus") {
          modulus = value;
        } else if (name === "number") {
          number = value;
          claimValueList += "<ic:ClaimValue Uri=\"http://schemas.t-labs.de/ws/2010/10/identity/claims/cardnumber\">" +
          "<ic:Value>" + value + "</ic:Value>" + 
          "</ic:ClaimValue>";
        } else {
          mwDebug("_card2token: unsupported Attributename name=" + name + " value=" + value);
          claimValueList += "<ic:ClaimValue Uri=\"http://schemas.t-labs.de/ws/2010/10/identity/claims/" + name + "\">" +
          "<ic:Value>" + value + "</ic:Value>" + 
          "</ic:ClaimValue>";
        }
        mwDebug("_card2token: claimValueList=" + claimValueList);
      }
    } catch (ee) {
      mwDebug("_card2token: exception=" + ee);
    }
  }
  
  
  domain = cardXml.@domain;
  if (domain) {
    domain = domain.toString();
    claimValueList += "<ic:ClaimValue Uri=\"http://schemas.t-labs.de/ws/2010/10/identity/claims/carddomain\">" +
    "<ic:Value>" + domain + "</ic:Value>" + 
    "</ic:ClaimValue>";
  }
  
  icon = cardXml.@icon;
  if (icon) {
    icon = icon.toString();
    claimValueList += "<ic:ClaimValue Uri=\"http://schemas.t-labs.de/ws/2010/10/identity/claims/imageref\">" +
    "<ic:Value>" + icon + "</ic:Value>" + 
    "</ic:ClaimValue>";
  }
  
  cardname = cardXml.@name;
  if (cardname) {
    cardname = cardname.toString();
  } else {
    cardname = "cardname";
  }
  
  if (domain === "Identity") {
  } else if (domain === "Payment") {
    claimValueList += "<ic:ClaimValue Uri=\"http://schemas.t-labs.de/ws/2010/10/identity/claims/cardname\">" +
    "<ic:Value>" + cardname + "</ic:Value>" + 
    "</ic:ClaimValue>";
  } else {
    mwDebug("_card2token: unsupported domain=" + domain);
  }
  mwDebug("_card2token: claimValueList=" + claimValueList);
  
//  infocard: choosenCard=<infocard>
//  <name>sechs</name>
//  <type>selfAsserted</type>
//  <version>1</version>
//  <id>19064</id>
//  <privatepersonalidentifier>446e7f7a527d75e24329ecd2982769311c36dff8</privatepersonalidentifier>
//  <ic:InformationCardPrivateData xmlns:ic="http://schemas.xmlsoap.org/ws/2005/05/identity">
//    <ic:MasterKey>446e7f7a527d75e24329ecd2982769311c36dff8</ic:MasterKey>
//    <ic:ClaimValueList>
//      <ic:ClaimValue Uri="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname">
//        <ic:Value>Axel</ic:Value>
//      </ic:ClaimValue>
//      <ic:ClaimValue Uri="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname">
//        <ic:Value>Nennker</ic:Value>
//      </ic:ClaimValue>
//      <ic:ClaimValue Uri="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress">
//        <ic:Value>axel@nennker.de</ic:Value>
//      </ic:ClaimValue>
//    </ic:ClaimValueList>
//  </ic:InformationCardPrivateData>
//  <ic:SupportedClaimTypeList xmlns:ic="http://schemas.xmlsoap.org/ws/2005/05/identity">
//    <ic:SupportedClaimType Uri="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname">
//      <ic:DisplayTag>Vorname:</ic:DisplayTag>
//    </ic:SupportedClaimType>
//    <ic:SupportedClaimType Uri="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname">
//      <ic:DisplayTag>Nachname:</ic:DisplayTag>
//    </ic:SupportedClaimType>
//    <ic:SupportedClaimType Uri="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress">
//      <ic:DisplayTag>Email:</ic:DisplayTag>
//    </ic:SupportedClaimType>
//    <ic:SupportedClaimType Uri="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier"/>
//  </ic:SupportedClaimTypeList>
//  <rpIds>ef328e98c0fd49dab2629400914924156616f2e2</rpIds>
//</infocard>

  try {
    var masterKey;
    if (modulus) {
      masterKey = modulus;
    } else {
      masterKey = "446e7f7a527d75e24329ecd2982769311c36dff8"; // FIXME
    }
  } catch (eee) {
    mwDebug("_card2token: exception=" + eee);
  }
  
  try {
    var infocard = "<infocard>" +
    "<id>" + cardname + "</id>" +
    "<privatepersonalidentifier>" + cardname + "</privatepersonalidentifier>" +
    "<ic:InformationCardPrivateData xmlns:ic=\"http://schemas.xmlsoap.org/ws/2005/05/identity\">" + 
      "<ic:MasterKey>" + masterKey + "</ic:MasterKey>" +
      "<ic:ClaimValueList>" + claimValueList + "</ic:ClaimValueList>" +
    "</ic:InformationCardPrivateData>" + 
    "</infocard>";
    mwDebug("_card2token: infocard=" + infocard);
  } catch (eeee) {
    mwDebug("_card2token: exception=" + eeee);
  }
  
  try {
    policy.type = "selfAsserted";
    policy.card = infocard;
    
    var serializedPolicy = JSON.stringify(policy);
    var sp = TokenIssuer.getToken(serializedPolicy);
    mwDebug("_card2token: sp=" + sp);
    var newPolicy = JSON.parse(sp);
    if (newPolicy.hasOwnProperty("tokenToReturn")) {
      var tokenToReturn = newPolicy.tokenToReturn;
      return tokenToReturn;
    }
    mwDebug("_card2token: no tokenToReturn" + sp);
    return null;
  } catch (getTokenException) {
    mwDebug("_card2token: getTokenException=" + getTokenException);
    return null;
  }
}

function pollForSelectedCardCallback(policy){
  try {
    mwDebug("pollForSelectedCardCallback: ");
    var card = TokenIssuer.getSelectedCard();
    if (card) {
      try {
        mwDebug("pollForSelectedCardCallback: " + card);
        if (policy.hasOwnProperty("timeoutId")) {
          window.clearInterval(policy["timeoutId"]);
        }
        
        var token = _card2token(policy, card);
        
           if ((!(window.arguments == undefined)) && (window.arguments.length > null)) {
             try {
               window.arguments[1](token);
             } catch (e) {
               Components.utils.reportError("mWallet.pollForSelectedCardCallback: " + e);
             }
        }
      } finally {
        window.close();
      }
    } else {
      var label = document.getElementById("notify");
      if (label != null) {
        var labelText = "Select a card on your phone";
        var stringsBundle = document.getElementById("string-bundle");
        if (stringsBundle) {
          var text = stringsBundle.getString('selectacardonyourphone');
          if (text) {
            labelText = text;
          }
        }
        label.setAttribute("value", labelText );
      }
    }
  } catch (eee) {
    Components.utils.reportError("mWallet.pollForSelectedCardCallback: exception=" + e);
  }
}

function mWalletLoad(policyParam){
  try {
    mwDebug("mWalletLoad start. href=" + window.document.location.href );
    var tokenIssuerInitialized = TokenIssuer.initialize();
    if (tokenIssuerInitialized == false) {
      mwDebug("mWalletUnload could not initialize the tokenissuer" );
      return;
    }
    
      var policy;
      if (policyParam == undefined) {
        policy = getPolicy();
      } else {
        policy = policyParam;
      }
  
    mwDebug("cardManagerLoad weiter gehts" );
    var serializedPolicy = JSON.stringify(policy);
    
    var cancelselector = document.getElementById('cancelselector');
    if (cancelselector) {
      cancelselector.addEventListener("click", cancel, false);
    }
    
    var phoneAvailable = isPhoneAvailable();
    if (phoneAvailable) {
      TokenIssuer.beginCardSelection();
      policy["timeoutId"] = window.setInterval(function(){pollForSelectedCardCallback(policy);}, 1000, true);
    } else {
      policy["timeoutId"] = window.setInterval(function(){pollForPhoneAvailableCallback(policy);}, 1000, true);
    }
  } catch (e) {
    mwDebug("mWalletLoad exception: " + e );
    throw e;
  }
}

