Components.utils.import("resource://infocard/IdentitySelectorDiag.jsm");
Components.utils.import("resource://infocard/InformationCardHelper.jsm");

var InformationCardUrlbar = {

  /*******************************************************************************
   * Desc:
   ******************************************************************************/
  showUrlbarIcon : function(doc, show, openidB) {
    var image = doc.getElementById("ic-url-bar-image");
    if (image !== null) {
      if (show === true) {
        if (doc.wrappedJSObject) {
          doc = doc.wrappedJSObject;
        }
        if (doc.__identityselector__ && doc.__identityselector__.last_card_image) {
          image.src = doc.__identityselector__.last_card_image;
        } else {
          if (openidB) {
            image.src = "chrome://infocard/content/img/openid-16x16.png";
          } else {
            image.src = "chrome://infocard/content/img/infocard_23x16.png";
          }
        }
      } else {
        // image.src = "chrome://infocard/content/img/infocard_23x16-crossed.png";
        image.src = "chrome://infocard/content/xmldap16x31.png";
      }
    } else {
      // the object is created before the status-bar is created
      IdentitySelectorDiag.logMessage("showUrlbarIcon", "Internal Warning: ic-url-bar-image not found");
    }
  },

  // ***********************************************************************
  // Method: tabSelected
  // ***********************************************************************
  tabSelected : function(event) {
    IdentitySelectorDiag.logMessage("tabSelected: ", "start");
    var browser = gBrowser.selectedTab.linkedBrowser;
    // browser is the XUL element of the browser that's just been selected
    var doc = gBrowser.selectedBrowser.contentDocument;
    if (doc instanceof HTMLDocument) {
      IdentitySelectorDiag.logMessage("tabSelected: ",
          "document is HTMLDocument: " + doc.location.href);
      if (doc.wrappedJSObject !== undefined) {
        IdentitySelectorDiag.logMessage("tabSelected: ",
            "document was wrapped: " + doc.location.href);
        doc = doc.wrappedJSObject;
      }
      if (doc.__identityselector__ === undefined) {
        IdentitySelectorDiag.logMessage("tabSelected: ", "this false");
        InformationCardUrlbar.showUrlbarIcon(document, false);
      } else {
        InformationCardUrlbar.cancelTimer(doc);
        if (((doc.__identityselector__.icLoginService !== undefined) && (doc.__identityselector__.icLoginPolicy !== undefined)) || (doc.__identityselector__.notificationBoxHidden !== undefined)) {
          InformationCardUrlbar.showUrlbarIcon(document, true);
        } else {
          IdentitySelectorDiag.logMessage("tabSelected: ", "that false");
          InformationCardUrlbar.showUrlbarIcon(document, false);
        }
      }

      var sidebarElement = document.getElementById("sidebar");
      if (sidebarElement !== null) {
        var sidebarWindow = sidebarElement.contentWindow;
        if (sidebarWindow && sidebarWindow.location.href == "chrome://infocard/content/cardSidebar.xul") {
          sidebarWindow.reload();
        }
      }
    } else {
      IdentitySelectorDiag.logMessage("tabSelected: ",
          "document is no HTMLDocument: " + doc.location.href);
    }
  },
    
    // ***********************************************************************
    // Method: onICardObjectLoaded
    // ***********************************************************************
   
    onICardObjectLoaded : function( event)
    {
        var target = event ? event.target : this;
        var doc;
       
        if( target.wrappedJSObject)
        {
                target = target.wrappedJSObject;
        }
        doc = target.ownerDocument;
        if( doc.wrappedJSObject)
        {
          doc = doc.wrappedJSObject;
        }
        IdentitySelectorDiag.logMessage("InformationCardUrlbar.onICardObjectLoaded",
        "document: " + doc.location.href);
        InformationCardUrlbar.showUrlbarIcon(document, true);
    },
    
    onLoad : function(event) {
        var doc = event.target;
        if( doc.wrappedJSObject)
        {
          doc = doc.wrappedJSObject;
        }

    var container = gBrowser.tabContainer; 
    container.addEventListener("TabSelect", InformationCardUrlbar.tabSelected, false);
    window.addEventListener("ICObjectLoaded",InformationCardUrlbar.onICardObjectLoaded, false);  
    window.addEventListener("DOMContentLoaded", 
        function(event) {InformationCardUrlbar.onDomContentLoaded(event);}, false );

    if (doc.__identityselector__ === undefined) {
      InformationCardUrlbar.showUrlbarIcon(document, false);
    } else {
      if (((doc.__identityselector__.icLoginService !== undefined) && (doc.__identityselector__.icLoginPolicy !== undefined)) || (doc.__identityselector__.notificationBoxHidden !== undefined)) {
        InformationCardUrlbar.showUrlbarIcon(document, true);
      } else {
        InformationCardUrlbar.showUrlbarIcon(document, false);
      }
    }

  
    },
    
    onDomContentLoaded : function(event) {
      var doc = event.originalTarget;
      if (doc instanceof HTMLDocument) {
        if (doc.wrappedJSObject !== undefined) {
          doc = doc.wrappedJSObject;
        }
        if (doc.__identityselector__ === undefined) {
          InformationCardUrlbar.showUrlbarIcon(document, false);
        } else {
          if (((doc.__identityselector__.icLoginService !== undefined) && (doc.__identityselector__.icLoginPolicy !== undefined))
              || (doc.__identityselector__.notificationBoxHidden !== undefined)) {
            InformationCardUrlbar.showUrlbarIcon(document, true);
          } else {
            InformationCardUrlbar.showUrlbarIcon(document, false);
          }
        }
      }
    },
    
    cancelTimer : function(doc) {
      if( doc.wrappedJSObject !== undefined) {
            doc = doc.wrappedJSObject;
        }
    if ((doc.__identityselector__ !== undefined) && (doc.__identityselector__.timer !== undefined)) {
      doc.__identityselector__.timer.cancel();
      delete doc.__identityselector__.timer;
    }
    },
    
    _findInformationCardObjectAndClick : function(doc) {
        var iLoop;
        var itemCount = 0;
       
        var objElems = doc.getElementsByTagName( "OBJECT");
       
        IdentitySelectorDiag.logMessage( "urlbar", "Found " +
                objElems.length + " object(s) on " + doc.location);
               
        for( iLoop = 0; iLoop < objElems.length; iLoop++)
        {
                var objElem = objElems[ iLoop];
                var objTypeStr = objElem.getAttribute( "TYPE");
               
                if( (objTypeStr !== null &&
                                objTypeStr.toLowerCase() == nsICardObjTypeStr) ||
                        objElem._type == nsICardObjTypeStr)
                {
                    IdentitySelectorDiag.logMessage( "urlbar", "Found infocard object on " + doc.location);
                    
//                    var event = document.createEvent("MouseEvents");
//                    event.initMouseEvent("click", true, true, window,
//                    0, 0, 0, 0, 0, false, false, false, false, 0, null);
//                    objElem.dispatchEvent(evt);
                    
                    var form = objElem.parentNode;
            while (form != null) {
              if (form.tagName != undefined && form.tagName == "FORM") {
                // the objElem is inside a form -> submit it
                var evnt = doc.createEvent("Event");
                evnt.initEvent("submit", true, true);
                form.dispatchEvent(evnt);
                return true;
              }
              form = form.parentNode;
            }
                }
        }
        return false;
    },
    
    urlbarClick : function() {
      var doc = gBrowser.selectedBrowser.contentDocument;
      if( doc.wrappedJSObject !== undefined) {
          doc = doc.wrappedJSObject;
      }
      IdentitySelectorDiag.logMessage( "urlbarClick", "clicked doc.location.href=" + doc.location.href);
      if (!(doc instanceof HTMLDocument)) { return; }

      if( !(doc.__identityselector__ === undefined)) {
         if ((doc.__identityselector__.icLoginService !== undefined) && (doc.__identityselector__.icLoginPolicy !== undefined)) {
           InformationCardHelper.callIdentitySelector(gBrowser.selectedBrowser);
            }
         else {
            if (InformationCardUrlbar._findInformationCardObjectAndClick(doc) === true) { return; }
            
            if (doc.__identityselector__.openidReturnToUri !== undefined) {
              InformationCardHelper.callIdentitySelector(gBrowser.selectedBrowser);
            } else {
              var policy = null;
              var wm = Components.classes["@mozilla.org/appshell/window-mediator;1"].getService(Components.interfaces.nsIWindowMediator);
              var win = wm.getMostRecentWindow("navigator:browser");
              var cardManager = win.openDialog("chrome://infocard/content/cardManager.xul",
                "Card Management", 
                "modal,chrome,resizable,width=800,height=640,centerscreen");
              }
          }
      } else {
//           if (doc.location !== undefined) {
//              IdentitySelectorDiag.logMessage( "urlbarClick", 
//                  "The site " + doc.location.href + " does not support Information Cards on this page. " + 
//                  "doc.__identityselector__ === undefined");
//              alert("The site " + doc.location.href + " does not support Information Cards.\n" + 
//                  "To learn more about Information Cards please visit the Information Card Foundation at\n" + 
//                  "https://informationcard.net/");
//              }
//           else {
//              IdentitySelectorDiag.logMessage( "urlbarClick", 
//                  "Information Cards are not supported here.\n" + 
//                  "doc.__identityselector__ === undefined");
//              alert("Information Cards are not supported here.\n" + 
//                  "To learn more about Information Cards please visit the Information Card Foundation at\n" + 
//                  "https://informationcard.net/");
//              }
//           }
          var policy = null;
          var cardManager = win.openDialog("chrome://infocard/content/cardManager.xul",
            "Card Management", 
            "modal,chrome,resizable,width=800,height=640,centerscreen");
          }
        }, 
        
        onProgress : function(doc, e) {
//      var req = e.target;
      if ((e !== null) && (e.totalSize !== 0)) {
        IdentitySelectorDiag.logMessage( "urlbarOnProgress", "progress " + (e.position / e.totalSize)*100);
      } else {
        //IdentitySelectorDiag.logMessage( "urlbarOnProgress", "progress ");
      }
//      var win = doc.defaultView;
      var urlBarImage = document.getElementById("ic-url-bar-image");
      if (urlBarImage !== null) {
        var src = urlBarImage.src;
        if (src !== null && src !== "") {
          var i = src.indexOf("-");
          if ( i > 0 ) {
            var tail = src.substring(i+1);
            var extIndex = tail.indexOf(".gif");
            if (extIndex > 0) {
              var ext = tail.substring(extIndex);
              var num = tail.substring(0,extIndex);
//              IdentitySelectorDiag.logMessage( "urlbarOnProgress", "ext=" + ext + " num=" + num + " tail=" + tail);
              var number = parseInt(num, 10);
              if (!isNaN(number) && (number >= 1) && (number <= 25)) {
                if (number === 25 ) {
                    urlBarImage.src = "chrome://infocard/content/img/infocard_23x16-1.gif";
                } else {
                  urlBarImage.src = "chrome://infocard/content/img/infocard_23x16-" + (number+1) + ext;
                }
              } else {
                urlBarImage.src = "chrome://infocard/content/img/infocard_23x16-1.gif";
              }
            } else {
              urlBarImage.src = "chrome://infocard/content/img/infocard_23x16-1.gif";
            }
          } else {
            urlBarImage.src = "chrome://infocard/content/img/infocard_23x16-1.gif";
          }
        } else {
          urlBarImage.src = "chrome://infocard/content/img/infocard_23x16-1.gif";
        }
      } else {
        IdentitySelectorDiag.logMessage( "urlbarOnProgress", "urlbar not found ");
      }
//      var percentComplete = (e.position / e.totalSize)*100;
    }
};

try {
  IdentitySelectorDiag.logMessage( "Urlbar", "start");
    window.addEventListener( "load", InformationCardUrlbar.onLoad, false);
//    window.addEventListener( "load", function(event){gBrowser.addEventListener("load", InformationCardUrlbar.onLoad, true);}, false);
} catch( e) {
  IdentitySelectorDiag.reportError( "urlbar window.addEventListener failed: ", e);
}



