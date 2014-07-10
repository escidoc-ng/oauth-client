/*
 * Copyright 2014 Michael Hoppe
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.fiz.oauthclient.servlet;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.json.JSONObject;

/**
 * @author mih
 */
public class OauthServlet extends HttpServlet {

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String clientId = "larch_admin";
        String clientSecret = "secret";

        if (request.getParameter("method").equals("login")) {
            try {
                OAuthClientRequest oauthRequest = OAuthClientRequest
                        .authorizationLocation("http://localhost:8080/oauth/authorize")
                        .setClientId(clientId)
                        .setResponseType("code")
                        .setRedirectURI("http://localhost:8088/oauthclient/oauth?method=token")
                        .buildQueryMessage();
                response.sendRedirect(oauthRequest.getLocationUri());

            } catch (OAuthSystemException e) {
                throw new IOException(e.getMessage());
            }
        }
        else if (request.getParameter("method").equals("token")) {
            try {
                OAuthAuthzResponse oar = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
                String code = oar.getCode();

                CloseableHttpClient httpclient = HttpClients.createDefault();
                HttpPost httpPost = new HttpPost("http://localhost:8080/oauth/token");
                List<NameValuePair> nvps = new ArrayList<NameValuePair>();
                nvps.add(new BasicNameValuePair("grant_type", "authorization_code"));
                nvps.add(new BasicNameValuePair("client_id", clientId));
                nvps.add(new BasicNameValuePair("client_secret", clientSecret));
                nvps.add(new BasicNameValuePair("code", code));
                nvps.add(new BasicNameValuePair("redirect_uri",
                        "http://localhost:8088/oauthclient/oauth?method=token"));
                httpPost.setEntity(new UrlEncodedFormEntity(nvps));
                String authorization = clientId + ":" + clientSecret;
                byte[] encodedBytes = Base64.encodeBase64(authorization.getBytes());
                authorization = "Basic " + new String(encodedBytes);
                httpPost.setHeader("Authorization", authorization);
                CloseableHttpResponse response2 = httpclient.execute(httpPost);

                String test = null;
                String token = null;
                try {
                    System.out.println(response2.getStatusLine());
                    HttpEntity entity2 = response2.getEntity();
                    test = EntityUtils.toString(entity2);
                    JSONObject obj = new JSONObject(test);
                    token = obj.getString("access_token");
                } finally {
                    response2.close();
                }

                String entity = "{\"label\" : \"Unnamed entity\"}";

                httpPost = new HttpPost("http://localhost:8080/entity");
                httpPost.setEntity(new StringEntity(entity));
                httpPost.setHeader("Content-type", "application/json; charset=UTF-8");

                authorization = "Bearer " + token;
                httpPost.setHeader("Authorization", authorization);
                response2 = httpclient.execute(httpPost);
                HttpEntity entity2 = response2.getEntity();
                test = EntityUtils.toString(entity2);
                System.out.println(test);

                HttpGet httpGet = new HttpGet("http://localhost:8080/entity/" + test);
                httpGet.setHeader("Authorization", authorization);
                response2 = httpclient.execute(httpGet);
                entity2 = response2.getEntity();
                test = EntityUtils.toString(entity2);
                System.out.println(test);

                PrintWriter out = response.getWriter();
                out.println("<html>");
                out.println("<body>");
                out.println(token);
                out.println("</body>");
                out.println("</html>");
            } catch (OAuthProblemException e) {
                throw new IOException(e.getMessage());
            }
        }
        else if (request.getParameter("method").equals("drei")) {
            PrintWriter out = response.getWriter();
            out.println("<html>");
            out.println("<body>");
            out.println("<h1>drei</h1>");
            out.println("</body>");
            out.println("</html>");
        }
    }
}
