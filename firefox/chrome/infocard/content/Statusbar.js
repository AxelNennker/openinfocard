Components.utils.import("resource://infocard/IdentitySelectorDiag.jsm");
Components.utils.import("resource://infocard/InformationCardHelper.jsm");

var InformationCardStatusbar = {

	/*******************************************************************************
	 * Desc:
	 ******************************************************************************/
	getUserIcon : function(doc) {
		 var userIconSrc = "chrome://infocard/content/img/infocard_23x16.png";
		 return userIconSrc;
	},
		 
	/*******************************************************************************
	 * Desc:
	 ******************************************************************************/
	showStatusbarIcon : function(doc, show, openidB) {
		var statusBarImage = doc.getElementById("ic-status-bar-image");
		if (statusBarImage !== null) {
			if (show === true) {
        if (openidB) {
          statusBarImage.src = "chrome://infocard/content/img/openid-16x16.png";
        } else {
          statusBarImage.src = this.getUserIcon(doc);
        }
			} else {
				statusBarImage.src = "chrome://infocard/content/img/infocard_23x16-crossed.png";
			}
		} else {
			// the object is created before the status-bar is created
			IdentitySelectorDiag.logMessage("showStatusbarIcon",
					"Internal Warning: ic-status-bar-image not found");
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
				InformationCardStatusbar.showStatusbarIcon(document, false);
			} else {
				InformationCardStatusbar.cancelTimer(doc);
				if (((doc.__identityselector__.icLoginService !== undefined) && (doc.__identityselector__.icLoginPolicy !== undefined)) || (doc.__identityselector__.notificationBoxHidden !== undefined)) {
					InformationCardStatusbar.showStatusbarIcon(document, true);
				} else {
					IdentitySelectorDiag.logMessage("tabSelected: ", "that false");
					InformationCardStatusbar.showStatusbarIcon(document, false);
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
        IdentitySelectorDiag.logMessage("InformationCardStatusbar.onICardObjectLoaded",
				"document: " + doc.location.href);
        InformationCardStatusbar.showStatusbarIcon(document, true);
    },
    
    onLoad : function(event) {
        var doc = event.target;
        if( doc.wrappedJSObject)
        {
        	doc = doc.wrappedJSObject;
        }

		var container = gBrowser.tabContainer; 
		container.addEventListener("TabSelect", InformationCardStatusbar.tabSelected, false);
		window.addEventListener("ICObjectLoaded",InformationCardStatusbar.onICardObjectLoaded, false);	
		window.addEventListener("DOMContentLoaded", 
				function(event) {InformationCardStatusbar.onDomContentLoaded(event);}, false );

		if (doc.__identityselector__ === undefined) {
			InformationCardStatusbar.showStatusbarIcon(document, false);
		} else {
			if (((doc.__identityselector__.icLoginService !== undefined) && (doc.__identityselector__.icLoginPolicy !== undefined)) || (doc.__identityselector__.notificationBoxHidden !== undefined)) {
				InformationCardStatusbar.showStatusbarIcon(document, true);
			} else {
				InformationCardStatusbar.showStatusbarIcon(document, false);
			}
		}

	
    },
    
    onDomContentLoaded : function(event) {
    	var doc = event.originalTarget;
        if (doc instanceof HTMLDocument) {
            if( doc.wrappedJSObject !== undefined) {
               doc = doc.wrappedJSObject;
            }
    		if (doc.__identityselector__ === undefined) {
    			InformationCardStatusbar.showStatusbarIcon(document, false);
    		} else {
    			if (((doc.__identityselector__.icLoginService !== undefined) && (doc.__identityselector__.icLoginPolicy !== undefined)) || (doc.__identityselector__.notificationBoxHidden !== undefined)) {
    				InformationCardStatusbar.showStatusbarIcon(document, true);
    			} else {
    				InformationCardStatusbar.showStatusbarIcon(document, false);
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
       
        IdentitySelectorDiag.logMessage( "statusbar", "Found " +
                objElems.length + " object(s) on " + doc.location);
               
        for( iLoop = 0; iLoop < objElems.length; iLoop++)
        {
                var objElem = objElems[ iLoop];
                var objTypeStr = objElem.getAttribute( "TYPE");
               
                if( (objTypeStr !== null &&
                                objTypeStr.toLowerCase() == nsICardObjTypeStr) ||
                        objElem._type == nsICardObjTypeStr)
                {
                    IdentitySelectorDiag.logMessage( "statusbar", "Found infocard object on " + doc.location);
                    
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
    
    statusbarClick : function() {
        var doc = gBrowser.selectedBrowser.contentDocument;
        if( doc.wrappedJSObject !== undefined) {
            doc = doc.wrappedJSObject;
        }
        IdentitySelectorDiag.logMessage( "statusbarClick", "clicked doc.location.href=" + doc.location.href);
        if (!(doc instanceof HTMLDocument)) { return; }

        if( !(doc.__identityselector__ === undefined)) {
           if ((doc.__identityselector__.icLoginService !== undefined) && (doc.__identityselector__.icLoginPolicy !== undefined)) {
         	  InformationCardHelper.callIdentitySelector(gBrowser.selectedBrowser, doc);
              }
           else {
        	    if (InformationCardStatusbar._findInformationCardObjectAndClick(doc) === true) return;
        	    
				if (doc.__identityselector__.openidReturnToUri !== undefined) {
					InformationCardHelper.callIdentitySelector(gBrowser.selectedBrowser, doc);
				} else {
					var msg = "";
					if (doc.__identityselector__.icLoginService === undefined) {
						msg = "doc.__identityselector__.icLoginService === undefined ";
					}
					if (doc.__identityselector__.icLoginPolicy === undefined) {
						msg = "doc.__identityselector__.icLoginPolicy === undefined ";
					}
					if (doc.location !== undefined) {
						IdentitySelectorDiag
								.logMessage(
										"statusbarClick",
										"The site "
												+ doc.location.href
												+ " does not support Information Cards on this page.\n"
												+ msg);
						alert("The site "
								+ doc.location.href
								+ " does not support Information Cards.\n"
								+ "To learn more about Information Cards please visit the Information Card Foundation at\n"
								+ "https://informationcard.net/");
					} else {
						IdentitySelectorDiag.logMessage("statusbarClick",
								"Information Cards are not supported here.\n"
										+ msg);
						alert("Information Cards are not supported here.\n"
								+ "To learn more about Information Cards please visit the Information Card Foundation at\n"
								+ "https://informationcard.net/");
					}
				}
			}
           }
        else {
           if (doc.location !== undefined) {
              IdentitySelectorDiag.logMessage( "statusbarClick", 
             		 "The site " + doc.location.href + " does not support Information Cards on this page. " + 
             		 "doc.__identityselector__ === undefined");
              alert("The site " + doc.location.href + " does not support Information Cards.\n" + 
             		 "To learn more about Information Cards please visit the Information Card Foundation at\n" + 
             		 "https://informationcard.net/");
              }
           else {
              IdentitySelectorDiag.logMessage( "statusbarClick", 
             		 "Information Cards are not supported here.\n" + 
             		 "doc.__identityselector__ === undefined");
              alert("Information Cards are not supported here.\n" + 
             		 "To learn more about Information Cards please visit the Information Card Foundation at\n" + 
             		 "https://informationcard.net/");
              }
           }
        
        }, 
        
        onProgress : function(doc, e) {
//    	var req = e.target;
    	if ((e !== null) && (e.totalSize !== 0)) {
    		IdentitySelectorDiag.logMessage( "statusbarOnProgress", "progress " + (e.position / e.totalSize)*100);
    	} else {
    		//IdentitySelectorDiag.logMessage( "statusbarOnProgress", "progress ");
    	}
//    	var win = doc.defaultView;
    	var statusBarImage = document.getElementById("ic-status-bar-image");
    	if (statusBarImage !== null) {
    		var src = statusBarImage.src;
    		if (src !== null && src !== "") {
    			var i = src.indexOf("-");
    			if ( i > 0 ) {
    				var tail = src.substring(i+1);
    				var extIndex = tail.indexOf(".gif");
    				if (extIndex > 0) {
    					var ext = tail.substring(extIndex);
    					var num = tail.substring(0,extIndex);
//    					IdentitySelectorDiag.logMessage( "statusbarOnProgress", "ext=" + ext + " num=" + num + " tail=" + tail);
    					var number = parseInt(num, 10);
    					if (!isNaN(number) && (number >= 1) && (number <= 25)) {
    						if (number === 25 ) {
        						statusBarImage.src = "chrome://infocard/content/img/infocard_23x16-1.gif";
    						} else {
    							statusBarImage.src = "chrome://infocard/content/img/infocard_23x16-" + (number+1) + ext;
    						}
    					} else {
    						statusBarImage.src = "chrome://infocard/content/img/infocard_23x16-1.gif";
    					}
    				} else {
    					statusBarImage.src = "chrome://infocard/content/img/infocard_23x16-1.gif";
    				}
    			} else {
    				statusBarImage.src = "chrome://infocard/content/img/infocard_23x16-1.gif";
    			}
    		} else {
    			statusBarImage.src = "chrome://infocard/content/img/infocard_23x16-1.gif";
    		}
    	} else {
    		IdentitySelectorDiag.logMessage( "statusbarOnProgress", "ic-status-bar-image not found ");
    	}
//    	var percentComplete = (e.position / e.totalSize)*100;
    }
};

try {
	IdentitySelectorDiag.logMessage( "Statusbar", "start");
    window.addEventListener( "load", InformationCardStatusbar.onLoad, false);
//    window.addEventListener( "load", function(event){gBrowser.addEventListener("load", InformationCardStatusbar.onLoad, true);}, false);
} catch( e) {
	IdentitySelectorDiag.reportError( "statusbar window.addEventListener failed: ", e);
}



