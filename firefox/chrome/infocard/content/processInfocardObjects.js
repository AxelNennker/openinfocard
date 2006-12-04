/*
 * Copyright (c) 2006, Chuck Mortimore - charliemortimore at gmail.com
 * xmldap.org
 * All rights reserved.
 *
 * Some code generated by the greasemokey compiler http://www.letitblog.com/greasemonkey-compiler/
 * Base64 by aardwulf.com
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the names xmldap, xmldap.org, xmldap.com nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

function do_infocard(e) {


    var doc = e.originalTarget;
    var icIter = document.evaluate("//object", doc, null, XPathResult.ANY_TYPE, null);
    var ic = icIter.iterateNext();
    while (ic) {

        var type = ic.getAttribute("type");

        if ((type == "application/x-informationcard") || (type == "application/x-informationCard") || (type == "application/infocard")) {

            hideMissingPlugin();

            var form = ic;
            while (form.tagName != "FORM") {

                form = form.parentNode;
            }

            var parent = ic.parentNode;

            var body = document.evaluate("//body", doc, null, XPathResult.ANY_TYPE, null).iterateNext();
            var formElm = doc.createElement("FORM");
            formElm.setAttribute("id", "firefox_infocard_form");
            formElm.setAttribute("method", "post");
            formElm.setAttribute("action", parent.getAttribute("action"));
            var input = doc.createElement("INPUT");
            input.setAttribute("name",ic.getAttribute("name"));
            input.setAttribute("type","hidden");
            formElm.appendChild(input);

            inputs = form.getElementsByTagName("input");
            for (var i = 0; i < inputs.length; i++) {
                var tmpInput = inputs[i];
                var clonedInput = tmpInput.cloneNode(true);
                formElm.appendChild(clonedInput);
            }
            body.appendChild(formElm);



            debug('init selector');
            initSelector(body);

            var img = parent.getElementsByTagName("img")[0];
            var inputs = parent.getElementsByTagName("input");
            var button;
            for (i = 0; i < inputs.length; i++) {

                if ( inputs[i].getAttribute("type") == "button" ) {

                    button = inputs[i];

                }

            }
            form.addEventListener("click", invokeSelector, false);

            if (!hideIntro) {

                if ( img != null ) {

                    img.setAttribute("onclick","");
                    promptIntroduction(body,img);

                } else if ( button != null ) {
                    button.setAttribute("onclick","");
                    promptIntroduction(body,button);


                } else {

                    form.setAttribute("onclick","");
                    promptIntroduction(body,form);

                }

            }

        }

        ic = icIter.iterateNext();

    }
}

function hideMissingPlugin(){

    var browserObject = document.getElementById("content");
    var notificationBox = browserObject.getNotificationBox();
    notificationBox.notificationsHidden = true;


}




function parseCard(infocard) {

    var policy = [];

    var params = infocard.getElementsByTagName("param");
    for (var i = 0; i < params.length; i++) {
        var name = params[i].getAttribute("Name");
        if ( name == "tokenType") {
	 policy["tokenType"] = params[i].getAttribute("Value");
	} else if ( name == "issuer") {
	 policy["issuer"] = params[i].getAttribute("Value");
	} else if ( name == "requiredClaims") {
	 policy["requiredClaims"] = params[i].getAttribute("Value");
	} else if ( name == "optionalClaims") {
	 policy["optionalClaims"] = params[i].getAttribute("Value");
	} else {
	 debug("Unhandled attribute: " + name);
	}
    }

    return policy;

}

function processCert(){


    var browser = document.getElementById("content");
    var secureUi = browser.securityUI;
    var sslStatusProvider = secureUi.QueryInterface(Components.interfaces.nsISSLStatusProvider);
    var sslStatus = sslStatusProvider.SSLStatus.QueryInterface(Components.interfaces.nsISSLStatus);
    return sslStatus.serverCert;


}

function getDer(cert){


    var length = {};
    var derArray = cert.getRawDER(length);
    var certBytes = '';
    for (var i = 0; i < derArray.length; i++) {
        certBytes = certBytes + String.fromCharCode(derArray[i]);
    }
    return btoa(certBytes);

}




function invokeSelector(aEvent){

    debug('start selector');

    var callback;
    var img = aEvent.originalTarget;
    var form = img.parentNode;
    while (form.tagName != "FORM") {
        form = form.parentNode;
    }
    var policy = parseCard(form);
    var certificate = processCert();
    var cert = getDer(certificate);

    policy["cert"] = cert;
    policy["cn"] = certificate.commonName;

    var doc = form.ownerDocument;
    var overlay = doc.getElementById('overlay');
    overlay.style.visibility = 'visible';


    var cardManager = window.openDialog("chrome://infocard/content/cardManager.xul","InfoCard Selector", "modal,chrome", policy, function (callbackData) { callback = callbackData;});


    overlay.style.visibility = 'hidden';

    //modal,,resizable=yes
    if ( callback == null ) return;


    var object = form.getElementsByTagName("object")[0];

    var body = form.parentNode;
    while (body.tagName != "BODY") {

        body = body.parentNode;

    }

    var infocardForm;
    var forms = body.getElementsByTagName("FORM");
    for (var i = 0; i < forms.length; i++) {
        var id = forms[i].getAttribute("id");
        if ( id == "firefox_infocard_form") {
            infocardForm = forms[i];
        }
    }

    var inputIter = infocardForm.getElementsByTagName("input");
    var input = inputIter[0];
    input.setAttribute("value",callback);

    infocardForm.submit();



}


var hideIntro = false;


function showIntroduction(e) {

    var prompt = e.originalTarget;
    var doc = prompt.ownerDocument;

    var overlay = doc.getElementById('overlay');
    overlay.style.visibility = 'visible';

    var intro = doc.getElementById('intro');
    intro.style.visibility = 'visible';


}


function hideIntroductionShow(e) {


    var prompt = e.originalTarget;
    var doc = prompt.ownerDocument;
    hideIntroduction(doc,false);

}

function hideIntroductionDontShow(e) {

    var prompt = e.originalTarget;
    var doc = prompt.ownerDocument;
    hideIntroduction(doc,true);

}


function hideIntroduction(doc, shouldHide) {

    hideIntro = shouldHide;

    if (hideIntro) {

        var prompt = doc.getElementById("introPrompt");
        prompt.style.visibility = 'hidden';

    }

    var intro = doc.getElementById('intro');
	intro.style.visibility = 'hidden';


    var overlay = doc.getElementById('overlay');
    overlay.style.visibility = 'hidden';


}



function promptIntroduction(body,target) {
    var position = findPos(target);
    debug('adding at pos ' + position);
    var intro = document.createElement("div");
    intro.setAttribute("id","introPrompt");
    intro.setAttribute("style","z-index:89;background-image: url('chrome://infocard/content/img/introduction.png'); min-width:130px; min-height: 31px; position: absolute;visibility: visible; cursor:help");
	intro.style.left = ( position[0] + target.clientWidth )+ 'px';
    intro.style.top = ( position[1] - 20 ) + 'px';
    intro.addEventListener("click", showIntroduction, false);
    body.appendChild(intro);

}


function findPos(obj)
{
	var curleft = curtop = 0;
	if (obj.offsetParent) {
		curleft = obj.offsetLeft
		curtop = obj.offsetTop
		while (obj = obj.offsetParent) {
			curleft += obj.offsetLeft
			curtop += obj.offsetTop
		}
	}
	return [curleft,curtop];
}



function initSelector(body){

    var w = document.width;
    var offset = (w - 660) / 2;

    var objOverlay = document.createElement("div");
    objOverlay.setAttribute('id','overlay');
    objOverlay.setAttribute('style','z-index: 90;');
    objOverlay.style.visibility = 'hidden';
    objOverlay.style.position = 'absolute';
    objOverlay.style.top = '0';
    objOverlay.style.left = '0';
    objOverlay.style.background = '#000000';
    objOverlay.style.height = document.height + 'px';
    objOverlay.style.width = document.width + 'px';
    objOverlay.style.opacity = '0.6';
    body.appendChild(objOverlay);


    var introOverlay = document.createElement("div");
    introOverlay.setAttribute('id','intro');
    introOverlay.setAttribute('style','z-index: 100;border: 1px solid grey; padding: 20px;font-family:trebuchet ms,verdana,helvetica;font-weight:bold;font-size:1.4em;');
    introOverlay.style.visibility = 'hidden';
    introOverlay.style.position = 'absolute';
    introOverlay.style.top = '40pt';
    introOverlay.style.left = offset + 'pt';
    introOverlay.style.background = '#FFFFFF';
    introOverlay.style.height = '480px';
    introOverlay.style.width = '640px';

    var p = document.createElement("p");
    p.setAttribute('style','min-width: 600px; max-width: 600px;');
    //p.textContent = 'Welcome to authentication with InfoCard.   When a InfoCard-enabled application or website wishes to obtain personal information about you, the site will prompt you to login with an InfoCard. Your Identity Selector will then appear, taking over the display of the browser and displaying the stored identities as virtual information cards. You may then select a card to use and the software contacts the issuer of the identity to obtain a digitally signed XML token that contains the requested information.   This is then securely sent to the requesting website.';
    p.textContent = 'Provide an introduction to InfoCard here!';
    introOverlay.appendChild(p);


    var p1 = document.createElement("p");
    p1.textContent = "    ";
    introOverlay.appendChild(p1);

    var closeAndShow = document.createElement("a");
    closeAndShow.setAttribute("href","");
    closeAndShow.textContent = "Thanks...please keep pointing out InfoCards!";
    closeAndShow.addEventListener("click", hideIntroductionShow, false);
    introOverlay.appendChild(closeAndShow);


    var p2 = document.createElement("p");
    p2.textContent = "    ";
    introOverlay.appendChild(p1);


    var closeAndDontShow = document.createElement("a");
    closeAndShow.setAttribute("href","");
    closeAndDontShow.textContent = "I get it...don't bother pointing out InfoCards anymore.";
    closeAndDontShow.addEventListener("click", hideIntroductionDontShow, false);
    introOverlay.appendChild(closeAndDontShow);


    body.appendChild(introOverlay);




}


function closeSelector(){

	var selector = document.getElementById('selector');
	selector.style.visibility = 'hidden';

	var overlay = document.getElementById('overlay');
    overlay.style.visibility = 'hidden';


}


window.addEventListener("load", function() {
    var appcontent = window.document.getElementById("appcontent");
    if (appcontent) {
        if (!appcontent.greased_infocard) {
            appcontent.greased_infocard = true;
            appcontent.addEventListener("DOMContentLoaded", do_infocard, false);
        }
    }
}, false);

