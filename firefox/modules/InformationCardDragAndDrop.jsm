var EXPORTED_SYMBOLS = ["InformationCardDragAndDrop"];  

Components.utils.import("resource://infocard/IdentitySelectorDiag.jsm");
Components.utils.import("resource://infocard/InformationCardHelper.jsm");

var InformationCardDragAndDrop = {

	extractDragData : function() {
		var cardId = null;
		try {
			var dragService = Cc["@mozilla.org/widget/dragservice;1"]
					.getService(Ci.nsIDragService);
			var dragSession = dragService.getCurrentSession();
			var sourceNode = dragSession.sourceNode;
			// Setup a transfer item to retrieve the file data
			var trans = Cc["@mozilla.org/widget/transferable;1"]
					.createInstance(Ci.nsITransferable);
			trans.addDataFlavor("application/x-informationcard+id");

			for ( var i = 0; i < dragSession.numDropItems; i++) {
				var uri = null;
				dragSession.getData(trans, i);
				var flavor = {}, data = {}, length = {};
				trans.getAnyTransferData(flavor, data, length);
				if (data) {
					var str = null;
					try {
						str = data.value.QueryInterface(Ci.nsISupportsString);
					} catch (ex) {
					}
					if (str !== null) {
						IdentitySelectorDiag.logMessage(
								"InformationCardDragAndDrop.extractDragData",
								"data=" + str);
						cardId = str;
						break;
						// only one
					} else {
						IdentitySelectorDiag.logMessage(
								"InformationCardDragAndDrop.extractDragData",
								"data=null");
					}
				}
			}
		} catch (e) {
			IdentitySelectorDiag.logMessage(
					"InformationCardDragAndDrop.extractDragData",e);
		}
		return cardId;
	},

  onICardObjectLoaded : function _onICardObjectLoaded(event) {
    IdentitySelectorDiag.logMessage("InformationCardDragAndDrop.onICardObjectLoaded", "start");
    var target = event.target;
    if (target.wrappedJSObject) {
      target = target.wrappedJSObject;
    }
    var form = target;
    while (form !== null) {
      if (form.tagName !== undefined && form.tagName == "FORM") {
        form.addEventListener("dragdrop", InformationCardDragAndDrop.onWindowDragDrop, false);
        if (form.hasChildNodes()) {
          var children = form.childNodes;
          for (var i = 0; i < children.length; i++) 
          {
            var child = children[i];
            child.addEventListener("dragdrop", InformationCardDragAndDrop.onWindowDragDrop, false);
          }
        }
        break;
      }
      form = form.parentNode;
    }
    
	},
	
	// ***********************************************************************
	// Method: onWindowDragDrop
	// ***********************************************************************
	onWindowDragDrop : function(event) {
		IdentitySelectorDiag.logMessage(
				"InformationCardDragAndDrop.onWindowDragDrop",
				"target.nodeName=", event.target.nodeName
						+ "\noriginalTarget.nodeName="
						+ event.originalTarget.nodeName
						+ "\ncurrentTarget.nodeName="
						+ event.currentTarget.nodeName);
		if (this.disabled === true) {
			IdentitySelectorDiag.logMessage(
					"InformationCardDragAndDrop.onWindowDragDrop",
					" ID selector is disabled. Exiting");
			return;
		}
		var fired = false;
		var target = event.target;
		if (target.wrappedJSObject) {
			target = target.wrappedJSObject;
		}
		var targetId = target.id;
		var doc = target.ownerDocument;
		var cardId = InformationCardDragAndDrop.extractDragData();
		
		if (cardId === null) {
			IdentitySelectorDiag.logMessage(
					"InformationCardDragAndDrop.onWindowDragDrop", "cardId == null");
			return;
		}
		
		if (targetId !== null) {
			IdentitySelectorDiag.logMessage(
					"InformationCardDragAndDrop.onWindowDragDrop", "targetId="+targetId);
			var object = InformationCardHelper.findRelatedObject(doc, targetId);
			if (object !== null) {
				// launch IdentitySelector with cardId
				IdentitySelectorDiag.logMessage(
						"InformationCardDragAndDrop.onWindowDragDrop",
						"launching IdentitySelector for card: " + cardId);
				doc.__identityselector__.targetElem = object;
				doc.__identityselector__.cardId = cardId;
				var form = target;
				while (form != null) {
					if (form.tagName != undefined && form.tagName == "FORM") {
						// the droptarget is inside a form -> submit it
						var trgt = form;
						var evnt = doc.createEvent("Event");
						evnt.initEvent("submit", true, true);
						trgt.dispatchEvent(evnt);
						fired = true;
						break;
					}
					form = form.parentNode;
				}
				if (!fired) {
					alert("The drop target is not inside a form\nDon't know how to submit token.");
				}
				// if (!fired) {
				// var trgt = doc;
				// var evnt = doc.createEvent( "Event");
				// evnt.initEvent( "CallIdentitySelector", true, true);
				// trgt.dispatchEvent( evnt);
				// }
				event.preventDefault();
				event.stopPropagation();
			} else {
				IdentitySelectorDiag.logMessage(
						"InformationCardDragAndDrop.onWindowDragDrop",
						"no object found for targetId=" + targetId
								+ " in document " + doc.location.href);
			}
		}
		if (fired == false) {
			IdentitySelectorDiag.logMessage(
					"InformationCardDragAndDrop.onWindowDragDrop", "cardId="+cardId);
			if (doc.__identityselector__.icLoginService !== undefined) {
				IdentitySelectorDiag.logMessage(
						"InformationCardDragAndDrop.onWindowDragDrop",
						"doc.__identityselector__.icLoginService="
								+ doc.__identityselector__.icLoginService);
			} else {
				Components.utils.reportError("InformationCardDragAndDrop.onWindowDragDrop" + 
						" doc.__identityselector__.icLoginService === undefined" +
						"\ndoc=" + doc.location.href);
				alert("login service is unknown");
				return false;
			}
			if (doc.__identityselector__.icLoginPolicy !== undefined) {
				IdentitySelectorDiag.logMessage(
						"InformationCardDragAndDrop.onWindowDragDrop",
						"doc.__identityselector__.icLoginPolicy="
								+ doc.__identityselector__.icLoginPolicy);
			} else {
				Components.util.reportError("InformationCardDragAndDrop.onWindowDragDrop" + 
						" doc.__identityselector__.icLoginPolicy === undefined" +
						"\ndoc=" + doc.location.href);
				alert("login policy is unknown");
				return false;
			}
			doc.__identityselector__.cardId = cardId;
			InformationCardHelper.callIdentitySelector(doc);
			event.preventDefault();
			event.stopPropagation();
		}
		return false;
	}

};

try {
  IdentitySelectorDiag.logMessage( "InformationCardDragAndDrop", "start");
} catch( e) {
  IdentitySelectorDiag.reportError( "InformationCardDragAndDrop Exception ", e);
}
