     function selfAssertedCallback() {

         var callbackdata = {};
         callbackdata.type = "selfAsserted";
         
         var selfAssertedRows = document.getElementById("selfAssertedRows");
         if (!selfAssertedRows) {
           // internal error
           Components.utils.reportError("cardWizard:selfAssertedCallback: could not find element with id=" + 
               "selfAssertedRows");
           return;
         }
         if (!selfAssertedRows.hasChildNodes()) { 
           Components.utils.reportError("cardWizard:selfAssertedCallback: no rows");
// selfAssertedRows.removeChild(selfAssertedRows.childNodes[0]); this does not
// make sense Axel 20100127
       }
         for (var i=0; i<selfAssertedRows.childNodes.length; i++) {
           var aRow = selfAssertedRows.childNodes[i];
           var aLabel = aRow.childNodes[0];
           var aText = aRow.childNodes[1];
           if ((aText.value !== undefined) && (aText.value !== "")) {
             var id = aText.getAttribute("id");
             if (id === "cardName") {
               callbackdata[id] = aText.value;
             } else {
               var object = {};
               object.displayTag = aLabel.value;
               object.claimValue = aText.value;
               callbackdata[id] = object;
               cardWizardDebug("selfAssertedCallback: callbackdata[" + id + "] = " + callbackdata[id]);
               }
           }
         }
         
         window.arguments[1](callbackdata);

         document.getElementById('card-window').cancel();


     }

     
     function next() {
         var menu = document.getElementById('cardType');
         var selectedItem = menu.selectedItem;
         var value = selectedItem.getAttribute('value');

         var wizard = document.getElementById('card-window');
         wizard.goTo(value);
// var typeObj = wizard.getPageById("type");
// var typeObj = document.getElementById('type');
// alert("boink: " + value);
// typeObj.setAttribute('next', value);

         return false;
     }

     
      var theCard = "";
     var theFile;
     var theData;          
  
  function onProgress(e) {
    var loadingStatus = document.getElementById("loadingStatus");
    var percentComplete = 0;
    if (e.totalSize > 0) {
      percentComplete = (e.position / e.totalSize)*100;
      loadingStatus.value = "loaded: " + percentComplete +"%";
    } else {
      // blinking
      if (loadingStatus.value.indexOf("loading") > 0) {
        loadingStatus.value = "";
      } else {
        loadingStatus.value = "loading";
      }
    }
  }

  function loadCardFromURL(url) {
    var req = new XMLHttpRequest();
    req.open('GET', url, true);
    req.onprogress = onProgress;
    req.onreadystatechange = function (aEvt) {
      if (req.readyState == 4) {
        var loadingStatus = document.getElementById("loadingStatus");
        if(req.status == 200) {
         loadingStatus.value = "loaded: 100%";
         theData = req.responseText;
        } else {
         loadingStatus.value = "Error loading page: " + req.status;
         cardWizardDebug(req.responseText);
        }
      }
    };
    req.send(null); 
  }
  
  function onPageShowManagedCard() {
    if (((window.arguments !== undefined)) && (window.arguments.length > null)) {
        var policy = window.arguments[0];
        if ((policy !== null) && (policy.hasOwnProperty("tokenType"))) {
        var tokenType = policy["tokenType"];
        if (tokenType === "urn:oasis:names:tc:IC:1.0:managedcard") {
          if (policy.hasOwnProperty("issuer")) {
            var textbox = document.getElementById("cardfile");
            textbox.value = policy["issuer"];
            textbox.setAttribute("readOnly", true);
            loadCardFromURL(textbox.value);
          }
        }
        }
    }
  }
  
     function pickFile() {

      var textbox = document.getElementById("cardfile");
        var button = document.getElementById('cardbutton');
        textbox.thefile = null;

       var nsIFilePicker = Components.interfaces.nsIFilePicker;
       var fp = Components.classes["@mozilla.org/filepicker;1"].createInstance(nsIFilePicker);
       fp.init(window, "Select a File", nsIFilePicker.modeOpen);
       fp.appendFilters( nsIFilePicker.filterAll );
       var res = fp.show();
       if (res === nsIFilePicker.returnOK) {
         textbox.thefile = fp.file;
         theData = getFile(fp.file);
         theFile = fp.file;
         textbox.value = textbox.thefile.path;
       } else {
         textbox.thefile = null;
         textbox.value = "";
       }

      theCard = textbox.value;
     }


     function getFile(file) {


         if (file != null) {

             var is = Components.classes["@mozilla.org/network/file-input-stream;1"].createInstance( Components.interfaces.nsIFileInputStream );
             var sstream = Components.classes["@mozilla.org/scriptableinputstream;1"].createInstance(Components.interfaces.nsIScriptableInputStream);

             is.init( file, 0x01, 00004, null);
             sstream.init(is);
             var data = "";
             var count = 0;

             while (sstream.available() > 0) {
                   count = sstream.available();
                   if (count > 2048) {
                     count = 2048;
                   }
                   data += sstream.read(count);
             }

             var stop;
       while ((stop = data.indexOf("?>")) > 0) {
        cardWizardDebug("import managed card: removing processing instructions" + stop);
        var newData = data.substring(stop+2);
        data = newData;
        cardWizardDebug("import managed card: " + data);
       }
       
       // remove garbaged / BOM
       if ((stop = data.indexOf('<')) > 0) {
         var newData = data.substring(stop);
         cardWizardDebug("removed garbage in front of first <");
         data = newData;
       }
       
         cardWizardDebug("Import managed card: " + data);
             return data;
         } else {
            return "";
         }

      }


      function parseCard(cardData) {
         cardWizardDebug("parseCard: " + cardData);

         var cardxml;
         
         try {
           cardxml = new XML(cardData);
         } catch (e) {
           alert(e);
             window.arguments[1](null);

             document.getElementById('card-window').cancel();
           return;
         }
         var dsig = new Namespace("dsig", "http://www.w3.org/2000/09/xmldsig#");
         var ic = new Namespace("ic", "http://schemas.xmlsoap.org/ws/2005/05/identity");
         var ic07 = new Namespace("ic07", "http://schemas.xmlsoap.org/ws/2007/01/identity");
         var wsid = new Namespace("wsid", "http://schemas.xmlsoap.org/ws/2006/02/addressingidentity");
         var wsa = new Namespace("wsa", "http://www.w3.org/2005/08/addressing");
         var mex = new Namespace("mex", "http://schemas.xmlsoap.org/ws/2004/09/mex");
         var wss = new Namespace("wss", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");

         var cardId = cardxml.dsig::Object.ic::InformationCard.ic::InformationCardReference.ic::CardId;
         var cardVersion = cardxml.dsig::Object.ic::InformationCard.ic::InformationCardReference.ic::CardVersion;
         var cardName = cardxml.dsig::Object.ic::InformationCard.ic::CardName;
         var cardImage = cardxml.dsig::Object.ic::InformationCard.ic::CardImage;
         var issuer = cardxml.dsig::Object.ic::InformationCard.ic::Issuer;
         
         var tokenServiceList = cardxml.dsig::Object.ic::InformationCard.ic::TokenServiceList.ic::TokenService;
// alert("tokenServiceList=" + tokenServiceList);
         
         var stsCert = cardxml.dsig::KeyInfo;

     var supportedTokenTypeList = cardxml.dsig::Object.ic::InformationCard.ic::SupportedTokenTypeList;

     var tokenServiceList = cardxml.dsig::Object.ic::InformationCard.ic::TokenServiceList;
// var cardUserCredential =
// cardxml.dsig::Object.ic::InformationCard.ic::TokenServiceList.ic::TokenService.ic::UserCredential;
     
// var cardHint =
// cardxml.dsig::Object.ic::InformationCard.ic::TokenServiceList.ic::TokenService.ic::UserCredential.ic::DisplayCredentialHint;
// var cardUid =
// cardxml.dsig::Object.ic::InformationCard.ic::TokenServiceList.ic::TokenService.ic::UserCredential.ic::UsernamePasswordCredential.ic::Username;
// var cardKeyIdentifier =
// cardxml.dsig::Object.ic::InformationCard.ic::TokenServiceList.ic::TokenService.ic::UserCredential.ic::X509V3Credential.dsig::X509Data.wss::KeyIdentifier;
// var cardPrivatePersonalIdentifier =
// cardxml.dsig::Object.ic::InformationCard.ic::TokenServiceList.ic::TokenService.ic::UserCredential.ic::SelfIssuedCredential.dsig::PrivatePersonalIdentifier;
     var requireAppliesTo = cardxml.dsig::Object.ic::InformationCard.ic::RequireAppliesTo;
     var requireStrongRecipientIdentity = cardxml.dsig::Object.ic::InformationCard.ic07::RequireStrongRecipientIdentity;
     
          cardWizardDebug(cardId);
          cardWizardDebug(cardName);
          cardWizardDebug(issuer);
// cardWizardDebug(cardHint);
// cardWizardDebug(cardUid);
// cardWizardDebug(cardKeyIdentifier);
// cardWizardDebug(cardPrivatePersonalIdentifier);
      cardWizardDebug(tokenServiceList);
      cardWizardDebug("stsCert: " + stsCert);
      cardWizardDebug("requireAppliesTo:" + requireAppliesTo);
      cardWizardDebug("SupportedTokenTypeList:"+ supportedTokenTypeList);
      
          var callbackdata = {};
          
          callbackdata["crdFileContent"] = cardData;
          
          callbackdata["type"] = "managedCard";
          callbackdata["cardId"] = cardId;
          callbackdata["cardVersion"] = cardVersion;
          callbackdata["cardName"] = cardName;
          callbackdata["cardImage"] = cardImage;
          callbackdata["issuer"] = issuer;
// callbackdata["hint"] = cardHint;
// callbackdata["uid"] = cardUid;
// callbackdata["KeyIdentifier"] = cardKeyIdentifier;
// callbackdata["PrivatePersonalIdentifier"] = cardPrivatePersonalIdentifier;
      callbackdata["tokenServiceList"] = tokenServiceList;
          callbackdata["stsCert"] = stsCert;
          callbackdata["supportedClaims"] = cardxml.dsig::Object.ic::InformationCard.ic::SupportedClaimTypeList;
          callbackdata["supportedTokenTypeList"] = supportedTokenTypeList;
          if (requireAppliesTo != null) {
              callbackdata["requireAppliesTo"] = true;
          }
          if (requireStrongRecipientIdentity != null) {
              callbackdata["requireStrongRecipientIdentity"] = true;
          }
          
      if ((!(window.arguments == undefined)) && (window.arguments.length > null)) {
          var policy = window.arguments[0];
          if (policy != null && policy.hasOwnProperty("tokenType")) {
          var tokenType = policy["tokenType"];
          if (tokenType == "urn:oasis:names:tc:IC:1.0:managedcard") {
            digestNewCard(callbackdata);
          }
          }
      }
    
      { 
        var func = window.arguments[1];
        if (typeof(func) == 'function') {
          window.arguments[1](callbackdata);
        }
      }
      
          document.getElementById('card-window').cancel();


      }

      function openidCallback() {

          var callbackdata = {};
          callbackdata["type"] = "openid";
          callbackdata["openid_url"] = document.getElementById("openid_url").value;
          callbackdata["cardName"] = document.getElementById("openid_url").value;
          callbackdata["cardId"] = document.getElementById("openid_url").value;
          window.arguments[1](callbackdata);

          document.getElementById('card-window').cancel();

      }

function loadCardWizard(){
  cardWizardDebug("loadCardWizard");
  if ((window.arguments !== undefined) && (window.arguments.length > 0)) {
    var policy = window.arguments[0];
    if ((policy !== null) && (policy.hasOwnProperty("tokenType"))) {
      var tokenType = policy["tokenType"];
      if (tokenType == "urn:oasis:names:tc:IC:1.0:managedcard") {
        document.getElementById('card-window').goTo('managedCard');
      }
      
      var selfAssertedRows = document.getElementById("selfAssertedRows");
      if (selfAssertedRows) {
        var requiredClaims = policy.requiredClaims;
        if (requiredClaims !== null) {
          requiredClaims = requiredClaims.replace(/\s+/g,' ');
          cardWizardDebug("requiredClaims=" + requiredClaims);
        }
        var claims = requiredClaims.split(' ');
        if (claims.length > 0) {
          for (var i=0; i<claims.length; i++) {
            var uri = claims[i];
            cardWizardDebug("uri=" + uri);
            if (uri == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier") {
              continue;
            }
            if (uri.indexOf(':') > 0) { // URNs and URIs must contain a colon
              var elt = document.getElementById(uri);
              if (!elt) { // not already in document
                cardWizardDebug("xxx");
                var aRow = document.createElement("row");
                var aLabel = document.createElement("textbox");
                aLabel.setAttribute("class", "lblTextBold");
                aLabel.setAttribute("value", uri);
                aLabel.setAttribute("tooltiptext", "required"); // this is not cropped
                var aTextBox = document.createElement("textbox");
                aTextBox.setAttribute("id", uri);
                aTextBox.setAttribute("value", "");
                aRow.appendChild(aLabel);
                aRow.appendChild(aTextBox);
                selfAssertedRows.appendChild(aRow);
              } else {
                cardWizardDebug("boink");
                var sibling = elt.previousSibling;
                if (sibling) {
                  cardWizardDebug("sibling.value=" + sibling.value); // label
                  sibling.setAttribute("class", "lblTextBold");
                  sibling.setAttribute("tooltiptext", "required"); // this is not cropped
                }
              }
            }
          }
        }
        cardWizardDebug("xyz");
        var optionalClaims = policy.optionalClaims;
        if (optionalClaims !== null) {
          optionalClaims = optionalClaims.replace(/\s+/g,' ');
          cardWizardDebug("optionalClaims=" + optionalClaims);
        }
        claims = optionalClaims.split(' ');
        if (claims.length > 0) {
          for (var i=0; i<claims.length; i++) {
            var uri = claims[i];
            cardWizardDebug("URI=" + uri);
            if (uri == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier") {
              continue;
            }
            if (uri.indexOf(':') > 0) { // URNs and URIs must contain a colon
              if (!document.getElementById(uri)) { // not already in document
                var aRow = document.createElement("row");
                var aLabel = document.createElement("textbox");
                aLabel.setAttribute("class", "lblText");
                aLabel.setAttribute("value", uri);
                var aTextBox = document.createElement("textbox");
                aTextBox.setAttribute("id", ""+ uri);
                aTextBox.setAttribute("value", "");
                aRow.appendChild(aLabel);
                aRow.appendChild(aTextBox);
                selfAssertedRows.appendChild(aRow);
              }
            }
          }
        }

      }
    }
  }
}
      
      function cardWizardDebug(msg) {
        var debug = Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService);
        debug.logStringMessage("cardWizard: " + msg);
      }
      



