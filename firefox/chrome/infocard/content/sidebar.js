
Components.utils.import("resource://infocard/IdentitySelectorDiag.jsm");
Components.utils.import("resource://infocard/InformationCardHelper.jsm");
Components.utils.import("resource://infocard/tokenissuer.jsm");
Components.utils.import("resource://infocard/CardstoreToolkit.jsm");

var OpeninfocardSidebar = {
    sbDebugObject : function(prefix, object, indent) {
      var msg = "";
      var count = 0;
      //if (indent > 3) return;
      var pre = "";
      for (var j=0; j<indent; j++) { pre += '\t'; }
      for (var i in object) {
        if (object.hasOwnProperty(i)) {
      
          var value = object[i];
          if (typeof(value) == 'object') {
            //sbDebugObject(value, indent+1);
            msg += pre + i + ' type=' + typeof(value) + ':' + value + '\n';
          } else if ((typeof(value) == 'string') || ((typeof(value) == 'boolean')) || ((typeof(value) == 'number'))) {
            msg += pre + ':' + i + '=' + value + '\n';
          } else {
            msg += pre + i + ' type=' + typeof(value) + '\n';
          }
        }
      }
      IdentitySelectorDiag.logMessage(prefix, msg);
    },

    getDoc : function(){
      var mainWindow = window.QueryInterface(Components.interfaces.nsIInterfaceRequestor)
      .getInterface(Components.interfaces.nsIWebNavigation)
      .QueryInterface(Components.interfaces.nsIDocShellTreeItem)
      .rootTreeItem
      .QueryInterface(Components.interfaces.nsIInterfaceRequestor)
      .getInterface(Components.interfaces.nsIDOMWindow);
      var browser = mainWindow.gBrowser;
      var doc = browser.contentDocument;
      IdentitySelectorDiag.logMessage("sidebar", "sidebarLoad mainwindow href=" + doc.location.href );
      if( doc.wrappedJSObject)
      {
        doc = doc.wrappedJSObject;
      }
      return doc;
    },
    
    getDer : function(cert,win){
      var length = {};
      var derArray = cert.getRawDER(length);
      var certBytes = '';
      for (var i = 0; i < derArray.length; i++) {
          certBytes = certBytes + String.fromCharCode(derArray[i]);
      }
      return win.btoa(certBytes);
    },

    sidebarDblClick : function(event) {
      IdentitySelectorDiag.logMessage("sidebarDblClick", "start");
      var choice = event.originalTarget;
      if (!choice) {
        IdentitySelectorDiag.reportError("sidebarDblClick", "internal error: sidebarDblClick: choice == undefined");
      }
      var selectedCardId = choice.getAttribute("cardid");
      if (!selectedCardId) {
        IdentitySelectorDiag.reportError("sidebarDblClick", "internal error: sidebarDblClick: selectedCardId == undefined");
      }
      IdentitySelectorDiag.logMessage("sidebarDblClick", "selectedCardId="+selectedCardId);
      var choosenCard = getCard(selectedCardId);
      if (choosenCard === null) {
        IdentitySelectorDiag.reportError("sidebarDblClick", "internal error: card not found: " + selectedCardId);
        return;
      }
      
      selectedCard = choosenCard;

      var doc = OpeninfocardSidebar.getDoc();
      if (!doc) { return; }
      IdentitySelectorDiag.logMessage("sidebarDblClick", "doc.location.href=" + doc.location.href);
      
      var objElems = doc.getElementsByTagName("OBJECT");
      for(var iLoop = 0; iLoop < objElems.length; iLoop++) {
        var objElem = objElems[iLoop];
        var objTypeStr = objElem.getAttribute("TYPE");
       
        if( (objTypeStr !== null) &&
             (objTypeStr == "application/x-informationcard"))
        {
          var selectorEvent = doc.createEvent( "Event");
          selectorEvent.initEvent("CallIdentitySelector", true, true);
          doc.__identityselector__.targetElem = objElem;
          doc.__identityselector__.cardid = selectedCardId;
          doc.dispatchEvent( selectorEvent);
        }
      }
      
    }




};

var ddObserver = {
  onDragStart: function (event, transferData, action) {
  var id = event.target.getAttribute("id");
  transferData.data = new TransferData();
  transferData.data.addDataForFlavour("text/html",id);
  }
};

var nsICardObjTypeStr = "application/x-informationcard";

function forEachICardItems( doc, callback)
{
        try
        {
                var iLoop;
                var itemCount = 0;
               
                // Process all of the information card objects in the document
                               
                var objElems = doc.getElementsByTagName( "OBJECT");
                var icardObjectCount = 0;
               
                IdentitySelectorDiag.logMessage( "processICardItems", "Found " +
                        objElems.length + " object(s) on " + doc.location);
                       
                for( iLoop = 0; iLoop < objElems.length; iLoop++)
                {
                        var objElem = objElems[ iLoop];
                        var objTypeStr = objElem.getAttribute( "TYPE");
                       
                        if( (objTypeStr !== null &&
                                        objTypeStr.toLowerCase() == nsICardObjTypeStr) ||
                                objElem._type == nsICardObjTypeStr)
                        {
                                callback(objElem, doc, "ICObjectLoaded");
                               
                                icardObjectCount++;
                        }
                }
               
                IdentitySelectorDiag.logMessage( "processICardItems", "Found " +
                        icardObjectCount + " ICard object(s) on " + doc.location);
                       
                // Process all of the information card elements in the document
               
                var icardElems = doc.getElementsByTagName( "IC:INFORMATIONCARD");
                var icardElementCount = icardElems.length;
               
                for( iLoop = 0; iLoop < icardElems.length; iLoop++)
                {
                        var icardElem = icardElems[ iLoop];
                        
                        callback(icardElem, doc, "ICElementLoaded");
                }
               
                IdentitySelectorDiag.logMessage( "processICardItems", "Found " +
                        icardElementCount + " ICard element(s) on " + doc.location);
                       
                return( icardObjectCount + icardElementCount);
        }
        catch( e)
        {
                IdentitySelectorDiag.debugReportError( "processICardItems", e);
        }
}

// this doc should be the doc of the main window (selected tab)
function getData(doc) {
  var data;
  if (doc.__identityselector__) {
    data = doc.__identityselector__.data;
  } else {
    data = {}
  }
  return data;
}

function createPolicy(doc, data) {
  var policy = {};
  return policy;
}
function sidebarLoad(){
  // infocard: sidebarLoad start. href=chrome://infocard/content/cardSidebar.xul
  IdentitySelectorDiag.logMessage("sidebar", "sidebarLoad start");

  var stringsBundle = document.getElementById("string-bundle");

  var doc = OpeninfocardSidebar.getDoc();
  if (!doc) { return; }
  IdentitySelectorDiag.logMessage("sidebar", "sidebarLoad doc.location.href=" + doc.location.href);
  var objects = [];
  var f = function(objElem, doc) {
    IdentitySelectorDiag.logMessage("sidebar", "objElem.name=" + objElem.name);
    objects.push(objElem);
  };
  
  forEachICardItems(doc, f);
  
  var data = getData(doc);
  if (!data) { return; }
  OpeninfocardSidebar.sbDebugObject("sidebarLoad data: ", data,0);
  var policy = createPolicy(doc, data);
  OpeninfocardSidebar.sbDebugObject("sidebarLoad policy: ", policy,0)

  var extraParamsCardId;
  if (doc.__identityselector__.cardId) {
    extraParamsCardId = doc.__identityselector__.cardId;
  }

  var rpIdentifier = null;
  
  var mainWindow = window.QueryInterface(Components.interfaces.nsIInterfaceRequestor)
  .getInterface(Components.interfaces.nsIWebNavigation)
  .QueryInterface(Components.interfaces.nsIDocShellTreeItem)
  .rootTreeItem
  .QueryInterface(Components.interfaces.nsIInterfaceRequestor)
  .getInterface(Components.interfaces.nsIDOMWindow);
  var browser = mainWindow.gBrowser;

  var sslCert = InformationCardHelper.getSSLCertFromBrowser(browser);
  if (sslCert) {
    policy.cert = OpeninfocardSidebar.getDer(sslCert,window);
    policy.cn = sslCert.commonName;
    rpIdentifier = computeRpIdentifier(policy.cert);
  } else {
    IdentitySelectorDiag.logMessage("sidebar", "sslCert is not set.");
  }
  IdentitySelectorDiag.logMessage("sidebar", "rpIdentifier=" + rpIdentifier);

  var cardFile;
  var cf = readCardStore();
  if (typeof(cf) == "string") {
    cardFile = new XML(cf);
  } else {
    cardFile = cf;
  }
  
  IdentitySelectorDiag.logMessage("sidebar", "cardFile=" + cardFile);
  
  var cardArea = document.getElementById("cardselection");
  var latestCard;
  var selectMe;
  var beenThere = false;
  var count = 0;
  var scrolledIntoView = false;
  
  IdentitySelectorDiag.logMessage("sidebar", "typeof(cardFile):" + typeof(cardFile));
  IdentitySelectorDiag.logMessage("sidebar", "cardFile.infocard.length():" + cardFile.infocard.length());
  
  var cardXmllist = cardFile.infocard;
  for (var i=0; i<cardXmllist.length(); i++) {
    var c = cardXmllist[i];
    IdentitySelectorDiag.logMessage("sidebar", "c.id=" + c.id);
    var cardClass = "contact";
    if (policy != null) {
      cardClass = computeCardClass(c, policy);
    }
    latestCard = createItem(c, cardClass, null, OpeninfocardSidebar.sidebarDblClick);
    selectMe = c;
    cardArea.appendChild(latestCard);
    count++;
  
    if (!beenThere) {
      if (rpIdentifier != null) {
        for each (rpId in c.rpIds) {
          IdentitySelectorDiag.logMessage("sidebar", "RpId:" + rpId + " RpIdentifier:" + rpIdentifier);
          if (rpId == rpIdentifier) {
            beenThere = true;
            if (scrolledIntoView == false) {
              if (cardArea.scrollBoxObject) {
                  var xpcomInterface = cardArea.scrollBoxObject.QueryInterface(Components.interfaces.nsIScrollBoxObject);
                  xpcomInterface.ensureElementIsVisible(latestCard);
              }
              scrolledIntoView = true;
            }
            break;
          }
        }
      }
    }
  }
    
  if ( count != 0) {
    if (policy != null) {
        var label = document.getElementById("notify");
        if (label != null) {
      var site = "Unknown";
      if (policy.hasOwnProperty("cn")) {
        site = policy["cn"];
      } else if (policy.hasOwnProperty("url")) {
        site = policy["url"];
      }
          var please = stringsBundle.getFormattedString('pleaseselectacard', [site]);
          label.setAttribute("value", please);
        }
    } else {
        var label = document.getElementById("notify");
        if (label != null) {
          label.setAttribute("value", "card management");
        }
    }
} else {
      var label = document.getElementById("notify");
      if (label != null) {
    var button = stringsBundle.getString('newcard');
        var youdont = stringsBundle.getFormattedString('youdonthaveanycards', [button]);
        label.setAttribute("value", youdont);
      }
  }
  if (policy != null) {
    var serializedPolicy = JSON.stringify(policy);
    if (TokenIssuer.initialize(java) == true) {
      var issuerLogoURL = TokenIssuer.getIssuerLogoURL(serializedPolicy);
      IdentitySelectorDiag.logMessage("sidebar", "issuerLogoURL=" + issuerLogoURL);
      if (issuerLogoURL != undefined) {
        var issuerlogo = document.getElementById("issuerlogo");
        issuerlogo.src = issuerLogoURL;
        issuerlogo.hidden = false;
        var issuerlogo_label = document.getElementById("issuerlogo_label");
              issuerlogo_label.hidden = false;
        var issuer_hbox = document.getElementById("issuer_hbox");
              issuer_hbox.hidden = false;
      }
    } else {
      IdentitySelectorDiag.logMessage("sidebar", "load: error initializing the TokenIssuer");
      IdentitySelectorDiag.logMessage("sidebar", "load: window.java=" + window.java + " window.document.location.href=" + window.document.location.href);
// alert("Error: Initializing the TokenIssuer");
      // return;
    }
  }
  if (policy != null) {
      var privacyUrl = policy["privacyUrl"];
        if (privacyUrl != null) {
      IdentitySelectorDiag.logMessage("sidebar", "privacyUrl " + privacyUrl);
             var showPrivacyStatementElm = document.getElementById('privacy_label');
             showPrivacyStatementElm.addEventListener("click", showPrivacyStatement, false);
             showPrivacyStatementElm.hidden = false;
      }
  }
  if (!beenThere) {
    if (policy != null) {
       if (policy.hasOwnProperty("cn")) {
         IdentitySelectorDiag.logMessage("sidebar", "never been here: " + policy["cn"]);
       } else if (policy.hasOwnProperty("url")) {
         IdentitySelectorDiag.logMessage("sidebar", "never been here: " + policy["url"]);
       } else {
         IdentitySelectorDiag.logMessage("sidebar", "never been here");
       }
    }
    if (policy !== null) { // no card management
      var firstTimeVisit = document.getElementById('firstTimeVisit');
      if (firstTimeVisit != null) {
        var labelText;
        try {
          labelText = stringsBundle.getString('firsttimevisit');
        } catch (e) {
         IdentitySelectorDiag.logMessage("sidebar", "firstTime: exception=" + e);
         labelText = "This is your first visit to this site. Think!";
        }
        IdentitySelectorDiag.logMessage("sidebar", "firstTime: " + labelText);
        firstTimeVisit.setAttribute("value", labelText);
        var firstTimeVisitBox = document.getElementById('firstTimeVisitBox');
        firstTimeVisitBox.setAttribute("hidden", "false");
      }
    } else { // else card management
      var firstTimeVisitBox = document.getElementById('firstTimeVisitBox');
      if (firstTimeVisitBox !== null) {
        firstTimeVisitBox.setAttribute("hidden", "false");
      } // else sidebar
    }
  }
  
  if (extraParamsCardId) {
    var choosenCard = getCard(extraParamsCardId);
    if ((choosenCard === undefined) || (choosenCard === null)) {
      Components.utils.reportError("sidebarLoad: extraParamsCardId=" + extraParamsCardId + " but card not found");
      alert("internal error: card not found in cardstore.");
      window.close();
      return;
    }
    setCard(choosenCard);
    var chossenCardElement = document.getElementById(extraParamsCardId);
    if (chossenCardElement !== null) {
      var xpcomInterface = cardArea.scrollBoxObject.QueryInterface(Components.interfaces.nsIScrollBoxObject);
      xpcomInterface.ensureElementIsVisible(chossenCardElement);
    }
  } else {
     IdentitySelectorDiag.logMessage("sidebar", "extraParamsCardId === undefined");
  }

}

//function sidebardOnLoad() {
//  IdentitySelectorDiag.logMessage("sidebar", "onLoad event");
// }
//
try {
  IdentitySelectorDiag.logMessage("sidebar", "start");
  
// var mainWindow =
// window.QueryInterface(Components.interfaces.nsIInterfaceRequestor)
// .getInterface(Components.interfaces.nsIWebNavigation)
// .QueryInterface(Components.interfaces.nsIDocShellTreeItem)
// .rootTreeItem
// .QueryInterface(Components.interfaces.nsIInterfaceRequestor)
// .getInterface(Components.interfaces.nsIDOMWindow);
//
// window.addEventListener( "load",
// function(event){mainWindow.gBrowser.addEventListener("load", sidebardOnLoad,
// true);}, false);
           
    // window.addEventListener( "unload", IcXrdsStartHelper.onUnload, false);
} catch( e) {
  IdentitySelectorDiag.reportError( "sidebar: ", e);
}

