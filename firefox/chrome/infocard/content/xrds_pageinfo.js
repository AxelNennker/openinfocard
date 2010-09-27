Components.utils.import("resource://infocard/OICCrypto.jsm");
Components.utils.import("resource://infocard/IdentitySelectorDiag.jsm");
Components.utils.import("resource://infocard/InformationCardHelper.jsm");
Components.utils.import("resource://infocard/CardstoreToolkit.jsm");

(function OICXrdsPageInfo() {

  function createItem(c){


    var hbox = document.createElement("hbox");
    hbox.setAttribute("cardid",c.id);
    hbox.setAttribute("id",c.id);

    var vbox = document.createElement("vbox");
    vbox.setAttribute("class","databox");
    vbox.setAttribute("flex","1");
    var labelName = document.createElement("label");
    labelName.setAttribute("class","lblname");
    labelName.setAttribute("value",c.name);
    labelName.setAttribute("cardid",c.id);
    var labelVersion = document.createElement("label");
    labelVersion.setAttribute("class","lblmail");
    labelVersion.setAttribute("value", "Version " + c.version);
    labelVersion.setAttribute("cardid",c.id);

    var imgurl = "";
    if ( c.type.toString() === "selfAsserted") {
        imgurl = c.carddata.selfasserted.imgurl.toString();
    } else if ( c.type.toString() === "managedCard") {
        imgurl = c.carddata.managed.image.toString();
    }
     //var picture = document.createElement("html:img");
    var picturebox = document.createElement("hbox");
    picturebox.setAttribute("flex", "0");
    picturebox.setAttribute("align", "center");
    var picture = document.createElement("image");
    if ( (imgurl === "") || (imgurl === undefined)) {

        if (c.type.toString() === "selfAsserted") {
            picture.setAttribute("src", "chrome://infocard/content/img/card.png");
        } else if (c.type.toString() === "openid") {
            picture.setAttribute("src", "chrome://infocard/content/img/openid.png");
        }
    } else {
        picture.setAttribute("src", imgurl);
    }

    picture.setAttribute("cardid", c.id);
    picture.setAttribute("class", "cardClass");
    picturebox.appendChild(picture);
    vbox.appendChild(picturebox);
    vbox.appendChild(labelName);
    vbox.appendChild(labelVersion);
    hbox.appendChild(vbox);
    return hbox;

  }
  
  function computeRpIdentifier(cert) {
    return OICCrypto.hex_sha1(cert);
  }
  
  function getDer(cert,win){
  
      var length = {};
      var derArray = cert.getRawDER(length);
      var certBytes = '';
      for (var i = 0; i < derArray.length; i++) {
          certBytes = certBytes + String.fromCharCode(derArray[i]);
      }
      return win.btoa(certBytes);
  
  }
  
  function openinfocard_pageinfoLoad() {
      var cardArea = document.getElementById("cardselection");
      while (cardArea.hasChildNodes() === true) {
        cardArea.removeChild(cardArea.childNodes[0]);
      }
  
      var mainDeck = document.getElementById("mainDeck");
      var width = window.innerWidth;
      
  //    for (var p in window) {
  //      if (window.hasOwnProperty(p)) {
  //        Components.utils.reportError("window." + p + "= " + window[p]);
  //      }
  //    }
      
    var rpIdentifier;
    
    var info = security._getSecurityInfo();
    var serverCert = null;
    if (info.cert && !info.isBroken) {
      serverCert = info.cert;
    }
  
    if (serverCert === null) {
      rpIdentifier = computeRpIdentifier(gDocument.location.href);
      Components.utils.reportError("rpIdentifier=" + rpIdentifier + " for URL " + gDocument.location.href);
    } else {
      var der = getDer(serverCert, window);
      rpIdentifier = computeRpIdentifier(der);
  //    Components.utils.reportError("rpIdentifier=" + rpIdentifier + " for CERT " + serverCert.organization);
    }
    
    var count = 0;
    var cardFile = CardstoreToolkit.readCardStore();
    
    for (var ci=0; ci<cardFile.infocard.length(); ci++) {
      var c = cardFile.infocard[i];
      var latestCard = createItem(c);
      for (var ri=0; ri<c.rpIds.length(); ri++) {
        var rpId = c.rpIds[ri];
        if (rpId == rpIdentifier) {
          cardArea.appendChild(latestCard);
          count++;
          break;
        }
      }
    }
      
      try {
        var textboxElt = document.getElementById("openinfocardTextbox");
        if (textboxElt !== null) {
          var text = null;
            var stringsBundle = document.getElementById("oic_pageinfo_sb");
          if (count > 0) {
            cardArea.setAttribute("hidden", false);
              text = stringsBundle.getString('cardusagehistory');
  //          if (text === null) {
  //            text = "Recorded Information Card usage at this site:";
  //          }
          } else {
              text = stringsBundle.getString('nocardusagehistory');
  //          if (text === null) {
  //            text = "There is no recorded history of Information Card usage.";
  //          }
          }
          textboxElt.setAttribute("value", text);
        } else {
          Components.utils.reportError("openinfocard_pageinfoLoad: openinfocardTextbox not found"); 
        }
    } catch (e) {
      Components.utils.reportError(e);
    }
  
  }

  try {
    // try to use the xrds_pageinfo.xpi component
    const CONTRACT_ID = "@openinfocard.org/xrds;1";
  
      var gObj = null;
      try {
        var cidClass = Components.classes[CONTRACT_ID];
      if (cidClass !== undefined) {
        gObj = cidClass.createInstance();
        gObj = gObj.QueryInterface(Components.interfaces.IXrdsComponent);
      } else {
        IdentitySelectorDiag.logMessage("InformationCardXrds", "the class " + CONTRACT_ID + " is not installed");
      }
      } catch(e1) {
        IdentitySelectorDiag.reportError("InformationCardXrds exception:", e1);
      }
      
      if (gObj !== null) {
        // xrds_pageinfo extension is installed
        window.addEventListener( "load", openinfocard_pageinfoLoad, false);
      }
  } catch(e) {
      Components.utils.reportError(e);
  }
})();