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
import org.apache.http.client.methods.HttpRequestBase;
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
 * @author mih <br>
 *         Requests: <br>
 *         ?method=login: sends redirect to ?method=token <br>
 *         ?method=token: sends oauth-token-request, puts token in session and displays token on page <br>
 * <br>
 *         Methods with Auth-Header:<br>
 *         if parameter authtype=token set, send request with token in Header.<br>
 *         Otherwise send request with Basic-Auth Header.<br>
 *         if parameter authstring=admin:admin provided, take that otherwise take user:user<br>
 * <br>
 *         ?method=create&workspaceId=jhfdfd: create entity and display values<br>
 *         ?method=logout: logout and then try creating an entity<br>
 *         eg ?method=/workspace/wfgwg/entity/dfgdgdg: send get-request to larch<br>
 */
public class OauthServlet extends HttpServlet {

    String baseUrl = "http://localhost:8080";

    String selfUrl = "http://localhost:8088";

    String selfContext = "/oauthclient";

    String clientId = "larch_admin";

    String clientSecret = "secret";

    String accessTokenAttributeName = "access-token";

    String authorization = "user:user";

    String entity = "{\"label\" : \"Unnamed entity\"}";

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        if (request.getParameter("method").equals("login")) {
            try {
                OAuthClientRequest oauthRequest = OAuthClientRequest
                        .authorizationLocation(baseUrl + "/oauth/authorize")
                        .setClientId(clientId)
                        .setResponseType("code")
                        .setRedirectURI(selfUrl + selfContext + "/oauth?method=token")
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
                HttpPost httpPost = new HttpPost(baseUrl + "/oauth/token");
                List<NameValuePair> nvps = new ArrayList<NameValuePair>();
                nvps.add(new BasicNameValuePair("grant_type", "authorization_code"));
                nvps.add(new BasicNameValuePair("client_id", clientId));
                nvps.add(new BasicNameValuePair("client_secret", clientSecret));
                nvps.add(new BasicNameValuePair("code", code));
                nvps.add(new BasicNameValuePair("redirect_uri",
                        selfUrl + selfContext + "/oauth?method=token"));
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

                request.getSession().setAttribute(accessTokenAttributeName, token);

                PrintWriter out = response.getWriter();
                out.println("<html>");
                out.println("<body>");
                out.println("logged in, token is " + token);
                out.println("</body>");
                out.println("</html>");
            } catch (OAuthProblemException e) {
                throw new IOException(e.getMessage());
            }
        }
        else if (request.getParameter("method").equals("create")) {
            CloseableHttpClient httpclient = HttpClients.createDefault();
            HttpPost httpPost =
                    new HttpPost(baseUrl + "/workspace/" + request.getParameter("workspaceId") + "/entity");
            httpPost.setEntity(new StringEntity(entity));
            httpPost.setHeader("Content-type", "application/json; charset=UTF-8");

            setAuthHeader(request, httpPost);
            CloseableHttpResponse response2 = httpclient.execute(httpPost);
            HttpEntity entity2 = response2.getEntity();
            String test = EntityUtils.toString(entity2);
            PrintWriter out = response.getWriter();
            out.println("<html>");
            out.println("<body>");
            out.println("status: " + response2.getStatusLine().toString() + "<br>");
            out.println("response-text: " + test);
            out.println("</body>");
            out.println("</html>");
        }
        else if (request.getParameter("method").equals("logout")) {
            CloseableHttpClient httpclient = HttpClients.createDefault();
            HttpPost httpPost = new HttpPost(baseUrl + "/logout");
            setAuthHeader(request, httpPost);
            CloseableHttpResponse response2 = httpclient.execute(httpPost);
            HttpEntity entity2 = response2.getEntity();
            String test = EntityUtils.toString(entity2);
            System.out.println(response2.getStatusLine().toString());
            System.out.println(test);

            httpPost = new HttpPost(baseUrl + "/entity");
            httpPost.setEntity(new StringEntity(entity));
            httpPost.setHeader("Content-type", "application/json; charset=UTF-8");

            setAuthHeader(request, httpPost);
            response2 = httpclient.execute(httpPost);
            entity2 = response2.getEntity();
            test = EntityUtils.toString(entity2);
            PrintWriter out = response.getWriter();
            out.println("<html>");
            out.println("<body>");
            out.println("status: " + response2.getStatusLine().toString() + "<br>");
            out.println("response-text: " + test);
            out.println("</body>");
            out.println("</html>");
        }
        else {
            CloseableHttpClient httpclient = HttpClients.createDefault();
            String method = request.getParameter("method");
            if (!method.startsWith("/")) {
                method = "/" + method;
            }
            HttpGet httpGet = new HttpGet(baseUrl + method);
            setAuthHeader(request, httpGet);
            CloseableHttpResponse response2 = httpclient.execute(httpGet);
            HttpEntity entity2 = response2.getEntity();
            String test = EntityUtils.toString(entity2);
            PrintWriter out = response.getWriter();
            out.println("<html>");
            out.println("<body>");
            out.println("status: " + response2.getStatusLine().toString() + "<br>");
            out.println("response-text: " + test);
            out.println("</body>");
            out.println("</html>");
        }
    }

    private void setAuthHeader(HttpServletRequest request, HttpRequestBase method) {
        if ("token".equals(request.getParameter("authtype"))) {
            String token = (String) request.getSession().getAttribute(accessTokenAttributeName);
            if (token != null && !token.isEmpty()) {
                String authorization = "Bearer " + token;
                method.setHeader("Authorization", authorization);
            }
        } else {
            String authorization;
            if (request.getParameter("authstring") != null) {
                authorization = request.getParameter("authstring");
            } else {
                authorization = this.authorization;
            }
            byte[] encodedBytes = Base64.encodeBase64(authorization.getBytes());
            authorization = "Basic " + new String(encodedBytes);
            method.setHeader("Authorization", authorization);
        }
    }
}
