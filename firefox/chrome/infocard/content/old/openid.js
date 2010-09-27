/*
 * Copyright (c) 2006, Chuck Mortimore - xmldap.org
 * All rights reserved.
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


var verified_id;
var openid_email;
var openid_nickname;
var openid_fullname;

var serverStarted = false;
var serverSocket;
var request;

function checkimmediate(uri) {

    var iframe = document.getElementById('openid_iframe');
    var window = iframe.contentWindow;
    iframe.setAttribute('src', uri);

}

function getParam(query, param) {

    var vars = query.split("&");
    for (var i=0;i<vars.length;i++) {
        var pair = vars[i].split("=");
        if (pair[0] == param) {
            return pair[1];
        }
    }
    return null;
}

function urlDecode(string){

    var utftext = unescape(string);

    string = "";
    var i = 0;
    var c = 0;
    var c1 = 0;
    var c2 = 0;

    while ( i < utftext.length ) {

        c = utftext.charCodeAt(i);

        if (c < 128) {
            string += String.fromCharCode(c);
            i++;
        }
        else if((c > 191) && (c < 224)) {
            c2 = utftext.charCodeAt(i+1);
            string += String.fromCharCode(((c & 31) << 6) | (c2 & 63));
            i += 2;
        }
        else {
            c2 = utftext.charCodeAt(i+1);
            c3 = utftext.charCodeAt(i+2);
            string += String.fromCharCode(((c & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63));
            i += 3;
        }

    }

    return string;
}

function handleOpenIdResponse(url) {

    var user_setup_url = getParam(url, "openid.user_setup_url");
    var identity = getParam(url, "openid.identity");

    icDebug("openid.user_setup_url: " + user_setup_url);
    icDebug("openid.identity: " + identity);
    if ( identity !== null ) {

        verified_id = urlDecode(identity);
        openid_email = urlDecode(getParam(url, "openid.sreg.email"));
        openid_nickname = urlDecode(getParam(url, "openid.sreg.nickname"));
        openid_fullname = urlDecode(getParam(url, "openid.sreg.fullname"));
        icDebug('Done processing openid');

        finalizeOpenId();

    } else if ( user_setup_url !== null ) {


        var se = document.createElement("iframe");
        se.setAttribute('id','openid_iframe2');
        se.setAttribute('style','min-width:795px; max-width:795px;min-height:445px;max-height:445px;');
        se.style.border = '0';
        var instructarea = document.getElementById('openID');
        instructarea.appendChild(se);
        se.contentWindow.location = urlDecode(user_setup_url) + "&openid.sreg.required=email,fullname,nickname";


    } else {

        alert('openid error');

    }
}

var async_listener = {
        input : Components.classes["@mozilla.org/scriptableinputstream;1"].createInstance(Components.interfaces.nsIScriptableInputStream),
	
	    onStopListening : function(serverSocket, status){},

	    onSocketAccepted : function(serverSocket, transport) {

//	    	icDebug('Got Server Connection');
	        var inputstream = transport.openInputStream(0,0,0);
//	        var input = Components.classes["@mozilla.org/scriptableinputstream;1"].createInstance(Components.interfaces.nsIScriptableInputStream);
	        this.input.init(inputstream);

	        var output = transport.openOutputStream(0,0,0);
	        var page = "HTTP/1.0 200 OK\nContent-type: text/html\n\n<body bgcolor='#333333'></body>";
	        output.write(page, page.length);
	        output.close();

	        var listener = {

	        	input : "";
	        
	            requestData : "",

	            onStartRequest: function(request, context){},

	            onStopRequest: function(request, context, status) {

	                this.input.close();
	                output.close();

	            },

	            onDataAvailable: function(request, context, stream, offset, count) {

	                this.requestData += this.input.read(count);
	                icDebug("bytes read: " + count);
	                var queryStart = this.requestData.indexOf("/?");
	                queryStart += 2;
	                var queryString = this.requestData.substring(queryStart, this.requestData.indexOf(" HTTP/1."));
	                handleOpenIdResponse(queryString);

	            }

	        };


	        var pump = Components.classes["@mozilla.org/network/input-stream-pump;1"].createInstance(Components.interfaces.nsIInputStreamPump);
	        pump.init(inputstream, -1, -1, 0, 0, false);
	        pump.asyncRead(listener,null);


	    }

};

function startServer(){

    if ( ! serverStarted )  {
        serverSocket = Components.classes["@mozilla.org/network/server-socket;1"].createInstance(Components.interfaces.nsIServerSocket);
        serverSocket.init(7055,false,-1);
        serverSocket.asyncListen(async_listener);
        serverStarted = true;
    }

}

function stopServer(){

    if ( serverStarted )  {
        serverSocket.close();
    }

}

function openid(server){

	icDebug("openid.js", "Starting openid server");

    startServer();


    var openid_url;
    if (server.indexOf('http') !== 0) {
        openid_url = "http://" + server;
    } else {
        openid_url = server;
    }

    icDebug("Checking openid_url: " + openid_url);

    var req = new XMLHttpRequest();
    req.open('GET', openid_url, false);
    req.setRequestHeader("User-Agent", "xmldap openid stack");
    req.send(null);
    if(req.status == 200) {

        var resp = req.responseText;
        var serverIndex = resp.indexOf("openid.server");
        var next = resp.substring(serverIndex);
        var hrefIndex = next.indexOf("href=");
        hrefIndex += 6;
        var subStr = next.substring(hrefIndex);
        var endAddr = subStr.indexOf('"');
        server = subStr.substring(0,endAddr);
        icDebug("Openid: " + server);
        try{
        	if (java === undefined) {
        		alert("openid: java == undefined");
        		return;
        	}
            var hostname = java.net.InetAddress.getLocalHost().getHostName();
            //this doesn't do any good on janrains trust warning
            //var url = server + "?openid.identity=" + openid_url + "&openid.return_to=http://" + hostname + ":7055/&openid.mode=checkid_immediate&openid.sreg.required=email,fullname,nickname";
            var returnTo = "http://localhost:7055";
            var url = server + "?openid.identity=" + openid_url + "&openid.return_to=" + returnTo + "/&openid.mode=checkid_immediate&openid.sreg.required=email,fullname,nickname";
            icDebug('Performing check_immediate: ' + url);
            checkimmediate(url);

        } catch (ex) {
            alert("Error loading remote iframe: " + ex);
        }

    }


}


