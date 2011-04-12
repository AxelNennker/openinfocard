/*
 * Copyright (c) 2007, Axel Nennker - http://axel.nennker.de/
 *                                  - http://ignisvulpis.blogspot.com/
 *                                  
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
 *     * The names of the contributors may NOT be used to endorse or promote products
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
 * 
 */


package org.xmldap.update;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


public class Update extends HttpServlet {

	String updateRdfBuffer = null;

    public void init(ServletConfig config) throws ServletException {

        super.init(config);

        String filename = "/WEB-INF/update.rdf";
            
		ServletContext application = getServletConfig().getServletContext();
		InputStream in = application.getResourceAsStream(filename);

		BufferedReader ins = new BufferedReader(new InputStreamReader(in));
		
		StringBuffer sb = new StringBuffer();
        try {
    		int c = -1;
    		char[] charBuf = null;
    		while (true) {
	    		int len = in.available();
	    		if (len > 0) {
	    			if (charBuf == null) {
	    				charBuf = new char[len];
	    			} else {
	    				if (len > charBuf.length) {
	    					charBuf = new char[len];
	    				}
	    			}
	    		} else {
	    			// available is not always relyable
	    			if (charBuf == null) {
	    				charBuf = new char[2048];
	    			} else {
	    				if (2048 > charBuf.length) {
	    					charBuf = new char[2048];
	    				}
	    			}
	    		}
	    		c = ins.read(charBuf, 0, charBuf.length);
	    		if (c == -1) {
	    			break;
	    		} else {
	    			sb.append(charBuf, 0, c);
	    		}
    		}
        } catch (IOException e) {
            throw new ServletException(e);
        } finally {
	    	try {
				in.close();
			} catch (IOException e) {}
    		try {
				ins.close();
			} catch (IOException e) {}
        }
   		updateRdfBuffer = new String(sb.toString());
		System.out.println("update.rdf: length=" + updateRdfBuffer.length());

    }


    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

    	String url = request.getRequestURL().toString();
		System.out.println("Update got a GET request: " + url);

        response.setContentType("application/rdf+xml; charset=utf-8");
		response.setContentLength(updateRdfBuffer.length());

		PrintWriter out = response.getWriter();
        try {
    		out.print(new String(updateRdfBuffer));
        } 
        finally {
    		out.flush();
    		out.close();
        }
        return;

    }

}
