

function openid2(server, finalizeOpenId, aDoc, extraParamsOpenIdReturnTo) {
	this.server = server;
	this.serverstarted = false;
	this.serversocket = 0;
	this.requestData = "";
	this.input = Components.classes["@mozilla.org/scriptableinputstream;1"].createInstance(Components.interfaces.nsIScriptableInputStream);
	this.pump = Components.classes["@mozilla.org/network/input-stream-pump;1"].createInstance(Components.interfaces.nsIInputStreamPump);
	this.logService = Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService);
	this.finalizeOpenId  = finalizeOpenId;
	this.aDoc = aDoc;
	this.extraParamsOpenIdReturnTo = extraParamsOpenIdReturnTo;
	
	this.startServer();
}

openid2.prototype =
{
	checkimmediate : function (uri) {
	    var iframe = this.aDoc.getElementById('openid_iframe');
	    iframe.setAttribute('src', uri);
	},

	getParam : function(query, param) {
	    var vars = query.split("&");
	    for (var i=0;i<vars.length;i++) {
	        var pair = vars[i].split("=");
	        if (pair[0] == param) {
	            return pair[1];
	        }
	    }
	    return null;
	},

	urlDecode : function(string){

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
	            var c3 = utftext.charCodeAt(i+2);
	            string += String.fromCharCode(((c & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63));
	            i += 3;
	        }

	    }
	    return string;
	}, 
	
	handleOpenIdResponse : function(url) {
	    var user_setup_url = this.getParam(url, "openid.user_setup_url");
	    var identity = this.getParam(url, "openid.identity");
	
	    if ( identity !== null ) {
	        this.logService.logStringMessage("handleOpenIdResponse: identity=" + identity);
	        var verified_id = this.urlDecode(identity);
	        var openid_email = this.urlDecode(this.getParam(url, "openid.sreg.email"));
	        var openid_nickname = this.urlDecode(this.getParam(url, "openid.sreg.nickname"));
	        var openid_fullname = this.urlDecode(this.getParam(url, "openid.sreg.fullname"));
	        this.logService.logStringMessage("handleOpenIdResponse:finalize: " + url);
	        this.finalizeOpenId(openid_nickname, openid_fullname, openid_email, verified_id, this);
	    } else if ( user_setup_url !== null ) {
	        var iframe = this.aDoc.getElementById('openid_iframe');
	        var uri = this.urlDecode(user_setup_url) + "&openid.sreg.required=email,fullname,nickname";
	        this.logService.logStringMessage("handleOpenIdResponse: user_setup_url=" + user_setup_url);
		    iframe.setAttribute('src', uri);
	    } else {
	        Components.util.reportError('openid error: ' + url);
	        throw 'openid error: ' + url;
	    }
	},
	
	onStartRequest: function(request, context){},

    onStopRequest: function(request, context, status) {
        this.input.close();
    },

    onDataAvailable: function(request, context, stream, offset, count) {
        this.requestData += this.input.read(count);
        var queryStart = this.requestData.indexOf("/?");
        queryStart += 2;
        var queryString = this.requestData.substring(queryStart, this.requestData.indexOf(" HTTP/1."));
        this.handleOpenIdResponse(queryString);
    },
		
	onStopListening : function(serverSocket, status){},
	
    onSocketAccepted : function(serverSocket, transport) {

        var inputstream = transport.openInputStream(0,0,0);
        this.input.init(inputstream);

        var output = transport.openOutputStream(0,0,0);
        try {
	        var page = "HTTP/1.0 200 OK\nContent-type: text/html\n\n<body bgcolor='#333333'></body>";
	        output.write(page, page.length);
        } catch (e) {
        	output.close();
        }

        this.pump.init(inputstream, -1, -1, 0, 0, false);
        this.pump.asyncRead(this,null);


    },

	doit : function() {
	    var openid_url;
	    if (this.server.indexOf('http') !== 0) {
	        openid_url = "http://" + this.server;
	    } else {
	        openid_url = this.server;
	    }
	
	    this.logService.logStringMessage("Checking openid_url: " + openid_url);
	
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
	        var openidServer = subStr.substring(0,endAddr);
	        this.logService.logStringMessage("Openid: " + openidServer);
	        try{
	        	var return_to;
	        	if (this.extraParamsOpenIdReturnTo !== undefined) {
	        		return_to = this.extraParamsOpenIdReturnTo;
	        	} else {
	        		return_to = "http://localhost:7055/";
	        	}
	        	var openid_sreg_required="email,fullname,nickname";
	            var url = openidServer + "?openid.identity=" + openid_url + "&openid.return_to=" + return_to + 
	            "&openid.mode=checkid_immediate&openid.sreg.required=" + openid_sreg_required;
	            this.logService.logStringMessage('Performing check_immediate: ' + url);
	            this.checkimmediate(url);
	
	        } catch (ex) {
	        	Components.util.reportError("Error loading remote iframe: " + ex);
	            throw "Error loading remote iframe: " + ex;
	        }
	    }
	},
	
	startServer: function()  {
	    if ( ! this.serverStarted )  {
	    	try {
		        this.serverSocket = Components.classes["@mozilla.org/network/server-socket;1"].createInstance(Components.interfaces.nsIServerSocket);
		        this.serverSocket.init(7055,false,-1);
		        this.serverSocket.asyncListen(this);
		        this.serverStarted = true;
			    this.logService.logStringMessage("openid2: started");
	    	} catch (e) {
	    		Components.util.reportError("openid2.startServer: " + e);
	    	}
	    } else {
	    	Components.util.reportError("openid2.startServer: already started");
	    }
	},
	
	stopServer : function() {
		if ( this.serverStarted )  {
			this.serverSocket.close();
	    }	
	}
};

