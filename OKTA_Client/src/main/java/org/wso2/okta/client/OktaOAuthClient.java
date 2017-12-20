/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * you may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.okta.client;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.*;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.AbstractKeyManager;
import org.wso2.carbon.apimgt.impl.factory.KeyManagerHolder;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.*;

/**
 * This class provides the implementation to use "Okta" for managing
 * OAuth clients and Tokens needed by WSO2 API Manager.
 */
public class OktaOAuthClient extends AbstractKeyManager {
    private static final Log log = LogFactory.getLog(OktaOAuthClient.class);

    private KeyManagerConfiguration configuration;

    /**
     * {@code APIManagerComponent} calls this method, passing KeyManagerConfiguration as a {@code String}.
     *
     * @param keyManagerConfiguration Configuration as a {@link org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration}
     * @throws APIManagementException
     */
    @Override
    public void loadConfiguration(KeyManagerConfiguration keyManagerConfiguration) throws APIManagementException {
        this.configuration = keyManagerConfiguration;
    }

    /**
     * This method will Register the client in Okta Authorization Server.
     *
     * @param oAuthAppRequest this object holds all parameters required to register an OAuth Client.
     * @throws APIManagementException
     */
    @Override
    public OAuthApplicationInfo createApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
        OAuthApplicationInfo oAuthApplicationInfo = oAuthAppRequest.getOAuthApplicationInfo();
        if (log.isDebugEnabled()) {
            log.debug("Creating an OAuth Client in OKTA Authorization Server");
        }
        KeyManagerConfiguration config = KeyManagerHolder.getKeyManagerInstance().getKeyManagerConfiguration();

        // Getting Client Registration Url and Access Token from Config.
//        String registrationEndpoint = config.getParameter(OktaConstants.CLIENT_REGISTRATION_ENDPOINT);
        String registrationEndpoint = "https://dev-763439.oktapreview.com/oauth2/v1/clients";
        String apiKey = config.getParameter(OktaConstants.REGISTRAION_API_KEY);

        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        BufferedReader reader = null;
        Map<String, Object> paramMap = new HashMap<String, Object>();
        try {
            // Create the JSON Payload that should be sent to OAuth Server.
            String jsonPayload = createJsonPayloadFromOauthApplication(oAuthApplicationInfo, paramMap);
            if (log.isDebugEnabled()) {
                log.debug("Payload for creating new client : " + jsonPayload);
            }

            HttpPost httpPost = new HttpPost(registrationEndpoint);
            httpPost.setEntity(new StringEntity(jsonPayload, OktaConstants.UTF_8));
            httpPost.setHeader(OktaConstants.HTTP_HEADER_CONTENT_TYPE, OktaConstants.APPLICATION_JSON);
            // Setting Authorization Header, with Access Token
            httpPost.setHeader(OktaConstants.AUTHORIZATION, OktaConstants.AUTHENTICATION_SSWS + apiKey);
            if (log.isDebugEnabled()) {
                log.debug("invoking HTTP request to create new client");
            }
            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();

            HttpEntity entity = response.getEntity();
            reader = new BufferedReader(new InputStreamReader(entity.getContent(), OktaConstants.UTF_8));
            JSONObject responseObject;
            // If successful a 201 will be returned.
            if (HttpStatus.SC_CREATED == statusCode) {
                responseObject = getParsedObjectByReader(reader);
                if (responseObject != null) {
                    oAuthApplicationInfo = createOAuthAppfromResponse(responseObject);

                    return oAuthApplicationInfo;
                }
            } else {
                handleException("Some thing wrong here while registering the new client " +
                        "HTTP Error response code is " + statusCode);
            }
        } catch (UnsupportedEncodingException e) {
            handleException("Encoding for the Response not-supported.", e);
        } catch (ParseException e) {
            handleException("Error while parsing response json", e);
        } catch (IOException e) {
            handleException("Error while reading response body ", e);
        } finally {
            if (reader != null) {
                IOUtils.closeQuietly(reader);
            }
            try {
                if (httpClient != null) {
                    httpClient.close();
                }
            } catch (IOException e) {
                log.error(e);
            }
        }
        return null;
    }

    /**
     * This method will update an existing OAuth Client.
     *
     * @param oAuthAppRequest Parameters to be passed to Authorization Server,
     *                        encapsulated as an {@code OAuthAppRequest}
     * @return Details of updated OAuth Client.
     * @throws APIManagementException
     */
    @Override
    public OAuthApplicationInfo updateApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
        OAuthApplicationInfo oAuthApplicationInfo = oAuthAppRequest.getOAuthApplicationInfo();
        if (log.isDebugEnabled()) {
            log.debug("Updating an OAuth Client in OKTA Authorization Server");
        }
        // We have to send the id with the update request.
        String clientId = oAuthApplicationInfo.getClientId();
//        String registrationEndpoint = configuration.getParameter(OktaConstants.CLIENT_REGISTRATION_ENDPOINT);
        String registrationEndpoint = "https://dev-763439.oktapreview.com/oauth2/v1/clients";
        String apiKey = configuration.getParameter(OktaConstants.REGISTRAION_API_KEY);
        registrationEndpoint += "/" + clientId;

        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        BufferedReader reader = null;
        Map<String, Object> paramMap = new HashMap<String, Object>();
        if (clientId != null) {
            paramMap.put(OktaConstants.CLIENT_ID, clientId);
        }

        try {
            String jsonPayload = createJsonPayloadFromOauthApplication(oAuthAppRequest.getOAuthApplicationInfo(), paramMap);
            if (log.isDebugEnabled()) {
                log.debug("Payload to update an OAuth client : " + jsonPayload);
            }
            HttpPut httpPut = new HttpPut(registrationEndpoint);
            httpPut.setEntity(new StringEntity(jsonPayload, OktaConstants.UTF_8));
            httpPut.setHeader(OktaConstants.HTTP_HEADER_CONTENT_TYPE, OktaConstants.APPLICATION_JSON);
            httpPut.setHeader(OktaConstants.AUTHORIZATION, OktaConstants.AUTHENTICATION_SSWS + apiKey);
            if (log.isDebugEnabled()) {
                log.debug("invoking HTTP request to update client");
            }
            HttpResponse response = httpClient.execute(httpPut);
            int statusCode = response.getStatusLine().getStatusCode();

            HttpEntity entity = response.getEntity();
            reader = new BufferedReader(new InputStreamReader(entity.getContent(), OktaConstants.UTF_8));
            JSONObject responseObject;
            if (statusCode == HttpStatus.SC_OK) {
                responseObject = getParsedObjectByReader(reader);
                if (responseObject != null) {
                    return createOAuthAppfromResponse(responseObject);
                } else {
                    handleException("ResponseObject is empty. Can not return oAuthApplicationInfo.");
                }
            } else {
                handleException("Some thing wrong here when updating the Client for key." + clientId + ". Error "
                        + "code" + statusCode);
            }
        } catch (UnsupportedEncodingException e) {
            handleException("Some thing wrong here when Updating a Client for key " + clientId, e);
        } catch (ParseException e) {
            handleException("Error while parsing response json", e);
        } catch (IOException e) {
            handleException("Error while reading response body from Server ", e);
        } finally {
            if (reader != null) {
                IOUtils.closeQuietly(reader);
            }
            try {
                if (httpClient != null) {
                    httpClient.close();
                }
            } catch (IOException e) {
                log.error(e);
            }
        }

        return null;
    }

    /**
     * Deletes OAuth Client from Authorization Server.
     *
     * @param clientId consumer key of the OAuth Client.
     * @throws APIManagementException
     */
    @Override
    public void deleteApplication(String clientId) throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug("Deleting an OAuth Client in OKTA Authorization Server for clientId:" + clientId);
        }

//        String registrationEndpoint = configuration.getParameter(OktaConstants.CLIENT_REGISTRATION_ENDPOINT);
        String registrationEndpoint = "https://dev-763439.oktapreview.com/oauth2/v1/clients";
        String apiKey = configuration.getParameter(OktaConstants.REGISTRAION_API_KEY);
        registrationEndpoint += "/" + clientId;

        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        try {
            HttpDelete httpDelete = new HttpDelete(registrationEndpoint);
            // Set Authorization Header
            httpDelete.addHeader(OktaConstants.AUTHORIZATION, OktaConstants.AUTHENTICATION_SSWS + apiKey);
            if (log.isDebugEnabled()) {
                log.debug("invoking HTTP request to delete the client ");
            }
            HttpResponse response = httpClient.execute(httpDelete);
            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode == HttpStatus.SC_NO_CONTENT) {
                log.info("OAuth Client for consumer Id " + clientId + " has been successfully deleted");
            } else {
                handleException("Problem occurred while deleting client for Consumer Key " + clientId);
            }
        } catch (IOException e) {
            handleException("Error while reading response body from Server ", e);
        } finally {
            try {
                if (httpClient != null) {
                    httpClient.close();
                }
            } catch (IOException e) {
                log.error(e);
            }
        }
    }

    /**
     * This method retrieves OAuth application details by given consumer key.
     *
     * @param clientId consumer key of the OAuth Client.
     * @return an {@code OAuthApplicationInfo} having all the details of an OAuth Client.
     * @throws APIManagementException
     */
    @Override
    public OAuthApplicationInfo retrieveApplication(String clientId) throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug("Retrieving an OAuth Client from OKTA Authorization Server");
        }

//        String registrationEndpoint = configuration.getParameter(OktaConstants.CLIENT_REGISTRATION_ENDPOINT);
        String registrationEndpoint = "https://dev-763439.oktapreview.com/oauth2/v1/clients";
        String apiKey = configuration.getParameter(OktaConstants.REGISTRAION_API_KEY);
        if (clientId != null) {
            registrationEndpoint += "/" + clientId;
        }

        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        BufferedReader reader = null;
        try {
            HttpGet request = new HttpGet(registrationEndpoint);
            // set authorization header.
            request.addHeader(OktaConstants.AUTHORIZATION, OktaConstants.AUTHENTICATION_SSWS + apiKey);
            if (log.isDebugEnabled()) {
                log.debug("invoking HTTP request to get the client details");
            }
            HttpResponse response = httpClient.execute(request);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            reader = new BufferedReader(new InputStreamReader(entity.getContent(), OktaConstants.UTF_8));
            Object responseJSON;

            if (statusCode == HttpStatus.SC_OK) {
                JSONParser parser = new JSONParser();
                responseJSON = parser.parse(reader);

                // If we have appended the clientId, then the response is a JSONObject if not the response is a JSONArray.
                if (responseJSON instanceof JSONArray) {
                    for (Object object : (JSONArray) responseJSON) {
                        JSONObject jsonObject = (JSONObject) object;
                        if ((jsonObject.get(OktaConstants.CLIENT_ID)).equals(clientId)) {
                            return createOAuthAppfromResponse(jsonObject);
                        }
                    }
                } else {
                    return createOAuthAppfromResponse((JSONObject) responseJSON);
                }
            } else {
                handleException("Something went wrong while retrieving client for consumer key " + clientId);
            }
        } catch (ParseException e) {
            handleException("Error while parsing response json.", e);
        } catch (IOException e) {
            handleException("Error while reading response body.", e);
        } finally {
            if (reader != null) {
                IOUtils.closeQuietly(reader);
            }
            try {
                if (httpClient != null) {
                    httpClient.close();
                }
            } catch (IOException e) {
                log.error(e);
            }
        }
        return null;
    }

    /**
     * Gets new access token and returns it in an AccessTokenInfo object.
     *
     * @param accessTokenRequest info on the token needed.
     * @return AccessTokenInfo
     * @throws APIManagementException in case of an issue
     */
    @Override
    public AccessTokenInfo getNewApplicationAccessToken(AccessTokenRequest accessTokenRequest)
            throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug("Get new client access token from Authorization Server");
        }
        AccessTokenInfo tokenInfo = new AccessTokenInfo();
        String accessToken = accessTokenRequest.getTokenToRevoke();
        if (accessToken != null) {
            revokeAccessToken(accessTokenRequest.getClientId(), accessTokenRequest.getClientSecret(), accessToken);
        }
        List<NameValuePair> parameters = new ArrayList<NameValuePair>();
        if (accessTokenRequest.getGrantType() == null || accessTokenRequest.getGrantType().isEmpty()) {
            parameters.add(new BasicNameValuePair(OktaConstants.GRANT_TYPE, OktaConstants.GRANT_TYPE_CLIENT_CREDENTIALS));
        } else {
            parameters.add(new BasicNameValuePair(OktaConstants.GRANT_TYPE, accessTokenRequest.getGrantType()));
        }

        String scopeString = convertToString(accessTokenRequest.getScope());

        if (scopeString == null || scopeString.isEmpty()) {
            handleException("Scope cannot be empty");
        } else {
            parameters.add(new BasicNameValuePair(OktaConstants.ACCESS_TOKEN_SCOPE, scopeString));
        }

        JSONObject responseJSON = getAccessToken(accessTokenRequest.getClientId(),
                accessTokenRequest.getClientSecret(), parameters);

        if (responseJSON != null) {
            updateTokenInfo(tokenInfo, responseJSON);
            log.info("OAuth token successfully validated");
            return tokenInfo;
        } else {
            tokenInfo.setTokenValid(false);
            tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_GENERAL_ERROR);
            log.info("OAuth token failed to validate");
        }

        return tokenInfo;
    }

    @Override
    public AccessTokenInfo getTokenMetaData(String accessToken) throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug("Getting token metadata from Authorization Server");
        }
        AccessTokenInfo tokenInfo = new AccessTokenInfo();

        KeyManagerConfiguration config = KeyManagerHolder.getKeyManagerInstance().getKeyManagerConfiguration();

//        String introspectionURL = config.getParameter(OktaConstants.INTROSPECTION_ENDPOINT);
        String introspectionURL = "https://dev-763439.oktapreview.com/oauth2/default/v1/introspect";
        String clientId = config.getParameter(OktaConstants.CLIENT_ID);
        String clientSecret = config.getParameter(OktaConstants.CLIENT_SECRET);
        String encodedCredencials = java.util.Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes());

        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        BufferedReader reader = null;

        try {
            List<NameValuePair> parameters = new ArrayList<NameValuePair>();
            parameters.add(new BasicNameValuePair(OktaConstants.TOKEN, accessToken));
            parameters.add(new BasicNameValuePair(OktaConstants.TOKEN_TYPE_HINT, OktaConstants.ACCESS_TOKEN));

            HttpPost httpPost = new HttpPost(introspectionURL);
            httpPost.setEntity(new UrlEncodedFormEntity(parameters));

            httpPost.setHeader(OktaConstants.AUTHORIZATION, OktaConstants.AUTHENTICATION_BASIC + encodedCredencials);
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to get token info");
            }
            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();

            JSONObject responseJSON;
            if (HttpStatus.SC_OK == statusCode) {
                HttpEntity entity = response.getEntity();
                reader = new BufferedReader(new InputStreamReader(entity.getContent(), OktaConstants.UTF_8));
                responseJSON = getParsedObjectByReader(reader);

                if (responseJSON != null) {
                    tokenInfo.setTokenValid((Boolean) responseJSON.get(OktaConstants.ACCESS_TOKEN_ACTIVE));

                    if (tokenInfo.isTokenValid()) {
                        long expiryTime = (Long) responseJSON.get(OktaConstants.ACCESS_TOKEN_EXPIRY);
                        tokenInfo.setValidityPeriod(expiryTime * 1000);

                        String tokScopes = (String) responseJSON.get(OktaConstants.ACCESS_TOKEN_SCOPE);

                        if (!(tokScopes == null || tokScopes.isEmpty())) {
                            tokenInfo.setScope(tokScopes.split("\\s+"));
                        }

                        tokenInfo.setIssuedTime(((Long) responseJSON.get(OktaConstants.ACCESS_TOKEN_ISSUED)) * 1000);
                        tokenInfo.setConsumerKey((String) responseJSON.get(OktaConstants.CLIENT_ID));
                        tokenInfo.setEndUserName((String) responseJSON.get(OktaConstants.ACCESS_TOKEN_USER_NAME));
                        tokenInfo.addParameter(OktaConstants.ACCESS_TOKEN_SUBJECT,
                                responseJSON.get(OktaConstants.ACCESS_TOKEN_SUBJECT));
                        tokenInfo.addParameter(OktaConstants.ACCESS_TOKEN_AUDIENCE,
                                responseJSON.get(OktaConstants.ACCESS_TOKEN_AUDIENCE));
                        tokenInfo.addParameter(OktaConstants.ACCESS_TOKEN_ISSUER,
                                responseJSON.get(OktaConstants.ACCESS_TOKEN_ISSUER));
                        tokenInfo.addParameter(OktaConstants.ACCESS_TOKEN_TYPE,
                                responseJSON.get(OktaConstants.ACCESS_TOKEN_TYPE));
                        tokenInfo.addParameter(OktaConstants.ACCESS_TOKEN_USER_ID,
                                responseJSON.get(OktaConstants.ACCESS_TOKEN_USER_ID));
                        tokenInfo.addParameter(OktaConstants.ACCESS_TOKEN_IDENTIFIER,
                                responseJSON.get(OktaConstants.ACCESS_TOKEN_IDENTIFIER));

                        return tokenInfo;
                    }
                } else {
                    log.error("Invalid Token " + accessToken);
                    tokenInfo.setTokenValid(false);
                    tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_ACCESS_TOKEN_INACTIVE);
                    return tokenInfo;
                }
            } // for other HTTP error codes we just pass generic message.
            else {
                log.error("Invalid Token " + accessToken);
                tokenInfo.setTokenValid(false);
                tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_ACCESS_TOKEN_INACTIVE);
                return tokenInfo;
            }
        } catch (ParseException e) {
            handleException("Error while parsing response json " + e.getMessage(), e);
        } catch (UnsupportedEncodingException e) {
            handleException("The Character Encoding is not supported. " + e.getMessage(), e);
        } catch (ClientProtocolException e) {
            handleException("HTTP request error has occurred while sending request to OAuth Provider. " +
                    e.getMessage(), e);
        } catch (IOException e) {
            handleException("Error has occurred while reading or closing buffer reader. " + e.getMessage(), e);
        } finally {
            if (reader != null) {
                IOUtils.closeQuietly(reader);
            }
            try {
                if (httpClient != null) {
                    httpClient.close();
                }
            } catch (IOException e) {
                log.error(e);
            }
        }

        return null;
    }

    @Override
    public KeyManagerConfiguration getKeyManagerConfiguration() throws APIManagementException {
        return configuration;
    }

    @Override
    public OAuthApplicationInfo buildFromJSON(String s) throws APIManagementException {
        return null;
    }

    /**
     * This method will be called when mapping existing OAuth Clients with Application in API Manager
     *
     * @param oAuthAppRequest Details of the OAuth Client to be mapped.
     * @return {@code OAuthApplicationInfo} with the details of the mapped client.
     * @throws APIManagementException
     */
    @Override
    public OAuthApplicationInfo mapOAuthApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
        return oAuthAppRequest.getOAuthApplicationInfo();
    }

    @Override
    public boolean registerNewResource(API api, Map resourceAttributes) throws APIManagementException {
        return true;
    }

    @Override
    public Map getResourceByApiId(String apiId) throws APIManagementException {
        return null;
    }

    @Override
    public boolean updateRegisteredResource(API api, Map resourceAttributes) throws APIManagementException {
        return true;
    }

    @Override
    public void deleteRegisteredResourceByAPIId(String apiID) throws APIManagementException {

    }

    @Override
    public void deleteMappedApplication(String s) throws APIManagementException {

    }

    @Override
    public Set<String> getActiveTokensByConsumerKey(String s) throws APIManagementException {
        return null;
    }

    @Override
    public AccessTokenInfo getAccessTokenByConsumerKey(String s) throws APIManagementException {
        return null;
    }

    /**
     * This method can be used to create a JSON Payload out of the Parameters defined in an OAuth Application.
     *
     * @param oAuthApplicationInfo Object that needs to be converted.
     * @return
     */
    private String createJsonPayloadFromOauthApplication(OAuthApplicationInfo oAuthApplicationInfo,
                                                         Map<String, Object> paramMap) throws APIManagementException {

//        if (oAuthApplicationInfo.getClientName() == null ||
//                oAuthApplicationInfo.getParameter(OktaConstants.CLIENT_REDIRECT_URIS) == null) {
//            throw new APIManagementException("Mandatory parameters (clientName/redirect_uris) missing");
//        }

        String clientName = oAuthApplicationInfo.getClientName();
        if (clientName != null) {
            paramMap.put(OktaConstants.CLIENT_NAME, clientName);
        }
        Object clientRedirectUris = oAuthApplicationInfo.getParameter(OktaConstants.CLIENT_REDIRECT_URIS);
        if (clientRedirectUris != null) {
            JSONArray redirectUris = (JSONArray) clientRedirectUris;//TODO
            paramMap.put(OktaConstants.CLIENT_REDIRECT_URIS, redirectUris);
        }
        Object clientResponseTypes = oAuthApplicationInfo.getParameter(OktaConstants.CLIENT_RESPONSE_TYPES);
        if (clientResponseTypes != null) {
            JSONArray responseTypes = (JSONArray) clientResponseTypes;//TODO
            paramMap.put(OktaConstants.CLIENT_RESPONSE_TYPES, responseTypes);
        }
        Object clientGrantTypes = oAuthApplicationInfo.getParameter(OktaConstants.CLIENT_GRANT_TYPES);
        if (clientGrantTypes != null) {
            JSONArray grantTypes = (JSONArray) clientGrantTypes;//TODO
            paramMap.put(OktaConstants.CLIENT_GRANT_TYPES, grantTypes);
        }
        Object clientPostLogoutRedirectUris = oAuthApplicationInfo.getParameter(
                OktaConstants.CLIENT_POST_LOGOUT_REDIRECT_URIS);
        if (clientPostLogoutRedirectUris != null) {
            JSONArray postLogoutRedirectUris = (JSONArray) clientPostLogoutRedirectUris;//TODO
            paramMap.put(OktaConstants.CLIENT_POST_LOGOUT_REDIRECT_URIS, postLogoutRedirectUris);
        }
        String tokenEndpointAuthMethod = (String) oAuthApplicationInfo.getParameter(
                OktaConstants.CLIENT_TOKEN_ENDPOINT_AUTH_METHOD);
        if (tokenEndpointAuthMethod != null) {
            paramMap.put(OktaConstants.CLIENT_TOKEN_ENDPOINT_AUTH_METHOD, tokenEndpointAuthMethod);
        }
        String clientUri = (String) oAuthApplicationInfo.getParameter(OktaConstants.CLIENT_URI);
        if (clientUri != null) {
            paramMap.put(OktaConstants.CLIENT_URI, clientUri);
        }
        String logoUri = (String) oAuthApplicationInfo.getParameter(OktaConstants.CLIENT_LOGO_URI);
        if (logoUri != null) {
            paramMap.put(OktaConstants.CLIENT_LOGO_URI, logoUri);
        }
        String initiateLoginUri = (String) oAuthApplicationInfo.getParameter(OktaConstants.CLIENT_INITIATE_LOGIN_URI);
        if (initiateLoginUri != null) {
            paramMap.put(OktaConstants.CLIENT_INITIATE_LOGIN_URI, initiateLoginUri);
        }
        String applicationType = (String) oAuthApplicationInfo.getParameter(OktaConstants.CLIENT_APPLICATION_TYPE);
        if (applicationType != null) {
            paramMap.put(OktaConstants.CLIENT_APPLICATION_TYPE, applicationType);
        }

        return JSONObject.toJSONString(paramMap);
    }

    /**
     * This method will create {@code OAuthApplicationInfo} object from a Map of Attributes.
     *
     * @param responseMap Response returned from server as a Map
     * @return OAuthApplicationInfo object will return.
     */
    private OAuthApplicationInfo createOAuthAppfromResponse(Map responseMap) {
        OAuthApplicationInfo info = new OAuthApplicationInfo();

        info.setClientId((String) responseMap.get(OktaConstants.CLIENT_ID));
        info.setClientSecret((String) responseMap.get(OktaConstants.CLIENT_SECRET));
        info.setClientName((String) responseMap.get(OktaConstants.CLIENT_NAME));
        info.addParameter(OktaConstants.CLIENT_REDIRECT_URIS, responseMap.get(OktaConstants.CLIENT_REDIRECT_URIS));
        Object clientIdIssuedAt = responseMap.get(OktaConstants.CLIENT_ID_ISSUED_AT);
        if (clientIdIssuedAt != null) {
            info.addParameter(OktaConstants.CLIENT_ID_ISSUED_AT, clientIdIssuedAt);
        }
        Object clientSecretExpiresAt = responseMap.get(OktaConstants.CLIENT_SECRET_EXPIRES_AT);
        if (clientSecretExpiresAt != null) {
            info.addParameter(OktaConstants.CLIENT_SECRET_EXPIRES_AT, clientSecretExpiresAt);
        }
        Object clientUri = responseMap.get(OktaConstants.CLIENT_URI);
        if (clientUri != null) {
            info.addParameter(OktaConstants.CLIENT_URI, clientUri);
        }
        Object logoUri = responseMap.get(OktaConstants.CLIENT_LOGO_URI);
        if (logoUri != null) {
            info.addParameter(OktaConstants.CLIENT_LOGO_URI, logoUri);
        }
        Object applicationType = responseMap.get(OktaConstants.CLIENT_APPLICATION_TYPE);
        if (applicationType != null) {
            info.addParameter(OktaConstants.CLIENT_APPLICATION_TYPE, applicationType);
        }
        Object postLogoutRedirectUris = responseMap.get(OktaConstants.CLIENT_POST_LOGOUT_REDIRECT_URIS);
        if (postLogoutRedirectUris != null) {
            info.addParameter(OktaConstants.CLIENT_POST_LOGOUT_REDIRECT_URIS, postLogoutRedirectUris);
        }
        Object responseTypes = responseMap.get(OktaConstants.CLIENT_RESPONSE_TYPES);
        if (responseTypes != null) {
            info.addParameter(OktaConstants.CLIENT_RESPONSE_TYPES, responseTypes);
        }
        Object grantTypes = responseMap.get(OktaConstants.CLIENT_GRANT_TYPES);
        if (grantTypes != null) {
            info.addParameter(OktaConstants.CLIENT_GRANT_TYPES, grantTypes);
        }
        Object tokenEndpointAuthMethod = responseMap.get(OktaConstants.CLIENT_TOKEN_ENDPOINT_AUTH_METHOD);
        if (tokenEndpointAuthMethod != null) {
            info.addParameter(OktaConstants.CLIENT_TOKEN_ENDPOINT_AUTH_METHOD, tokenEndpointAuthMethod);
        }
        Object initiateLoginUri = responseMap.get(OktaConstants.CLIENT_INITIATE_LOGIN_URI);
        if (initiateLoginUri != null) {
            info.addParameter(OktaConstants.CLIENT_INITIATE_LOGIN_URI, initiateLoginUri);
        }

        return info;
    }

    /**
     * Revokes an access token.
     *
     * @param clientId     clientId of the oauth client
     * @param clientSecret clientSecret of the oauth client
     * @param accessToken  token being revoked
     * @throws APIManagementException thrown in case of issue
     */
    private void revokeAccessToken(String clientId, String clientSecret, String accessToken) throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug("Revoke access token from Authorization Server");
        }
        CloseableHttpClient httpClient = HttpClientBuilder.create().build();

        try {
            List<NameValuePair> nvps = new ArrayList<NameValuePair>();
            nvps.add(new BasicNameValuePair(OktaConstants.TOKEN, accessToken));
            nvps.add(new BasicNameValuePair(OktaConstants.TOKEN_TYPE_HINT, OktaConstants.ACCESS_TOKEN));

//            HttpPost httpPost = new HttpPost(configuration.getParameter(OktaConstants.CLIENT_REVOKE_ENDPOINT));
            HttpPost httpPost = new HttpPost("https://dev-763439.oktapreview.com/oauth2/default/v1/revoke");
            httpPost.setEntity(new UrlEncodedFormEntity(nvps));
            String encodedCredencials = java.util.Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes());

            httpPost.setHeader(OktaConstants.AUTHORIZATION, OktaConstants.AUTHENTICATION_BASIC + encodedCredencials);
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to revoke access token");
            }

            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode == HttpStatus.SC_OK) {
                log.info("OAuth accessToken has been successfully revoked");
            } else {
                handleException("Problem occurred while revoking the accesstoken for Consumer Key " + clientId);
            }
        } catch (UnsupportedEncodingException e) {
            handleException("The Character Encoding is not supported. " + e.getMessage(), e);
        } catch (ClientProtocolException e) {
            handleException("HTTP request error has occurred while sending request to OAuth Provider. " +
                    e.getMessage(), e);
        } catch (IOException e) {
            handleException("Error has occurred while reading or closing buffer reader. " + e.getMessage(), e);
        } finally {
            try {
                if (httpClient != null) {
                    httpClient.close();
                }
            } catch (IOException e) {
                log.error(e);
            }
        }
    }

    /**
     * Can be used to parse {@code BufferedReader} object that are taken from response stream, to a {@code JSONObject}.
     *
     * @param reader {@code BufferedReader} object from response.
     * @return JSON payload as a name value map.
     */
    private JSONObject getParsedObjectByReader(BufferedReader reader) throws ParseException, IOException {

        JSONObject parsedObject = null;
        JSONParser parser = new JSONParser();
        if (reader != null) {
            parsedObject = (JSONObject) parser.parse(reader);
        }
        return parsedObject;
    }

    /**
     * common method to throw exceptions. This will only expect one parameter.
     *
     * @param msg error message as a string.
     * @throws APIManagementException
     */
    private void handleException(String msg) throws APIManagementException {
        log.error(msg);
        throw new APIManagementException(msg);
    }

    /**
     * common method to throw exceptions.
     *
     * @param msg this parameter contain error message that we need to throw.
     * @param e   Exception object.
     * @throws APIManagementException
     */
    private void handleException(String msg, Exception e) throws APIManagementException {
        log.error(msg, e);
        throw new APIManagementException(msg, e);
    }

    /**
     * Returns a space separate list of the contents of the stringArray.
     *
     * @param stringArray an array of strings.
     * @return space separated string
     */
    public static String convertToString(String[] stringArray) {
        if (stringArray != null) {
            StringBuilder sb = new StringBuilder();
            List<String> strList = Arrays.asList(stringArray);

            for (String s : strList) {
                sb.append(s);
                sb.append(" ");
            }

            return sb.toString().trim();
        }

        return null;
    }

    /**
     * Gets an access token.
     *
     * @param clientId     clientId of the oauth client
     * @param clientSecret clientSecret of the oauth client
     * @param parameters   list of request parameters
     * @return an {@code JSONObject}
     * @throws APIManagementException thrown in case of issue
     */
    private JSONObject getAccessToken(String clientId, String clientSecret, List<NameValuePair> parameters) throws
            APIManagementException {
        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        BufferedReader reader = null;
        try {
            HttpPost httpPost = new HttpPost("https://dev-763439.oktapreview.com/oauth2/default/v1/token");//TODO
            httpPost.setEntity(new UrlEncodedFormEntity(parameters));

            String encodedCredentials = java.util.Base64.getEncoder().encodeToString((clientId + ":" + clientSecret)
                    .getBytes());
            httpPost.setHeader(OktaConstants.AUTHORIZATION, OktaConstants.AUTHENTICATION_BASIC + encodedCredentials);
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to get the accesstoken");
            }
            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            reader = new BufferedReader(new InputStreamReader(entity.getContent(), OktaConstants.UTF_8));
            JSONObject responseJSON;

            if (HttpStatus.SC_OK == statusCode) {
                responseJSON = getParsedObjectByReader(reader);
                if (responseJSON != null) {
                    log.info("JSON response after getting new access token: " + responseJSON.toJSONString());
                    return responseJSON;
                }
            } else {
                log.error("Failed to get accessToken for clientId " + clientId + " with StatusCode:" + statusCode);
            }
        } catch (UnsupportedEncodingException e) {
            handleException("The Character Encoding is not supported. " + e.getMessage(), e);
        } catch (ParseException e) {
            handleException("Error while parsing response json " + e.getMessage(), e);
        } catch (IOException e) {
            handleException("Error has occurred while reading or closing buffer reader. " + e.getMessage(), e);
        } finally {
            if (reader != null) {
                IOUtils.closeQuietly(reader);
            }
            try {
                if (httpClient != null) {
                    httpClient.close();
                }
            } catch (IOException e) {
                log.error(e);
            }
        }
        return null;
    }

    /**
     * Update the access token info after revoking the access token
     *
     * @param tokenInfo
     * @param responseJSON
     * @return
     */
    private AccessTokenInfo updateTokenInfo(AccessTokenInfo tokenInfo, JSONObject responseJSON) {
        if(log.isDebugEnabled()) {
            log.debug("Update the access token info after revoking the access token");
        }
        tokenInfo.setAccessToken((String) responseJSON.get(OktaConstants.ACCESS_TOKEN));

        Long expireTime = (Long) responseJSON.get(OktaConstants.ACCESS_TOKEN_EXPIRES_IN);

        if (expireTime == null) {
            tokenInfo.setTokenValid(false);
            tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_ACCESS_TOKEN_EXPIRED);
            return tokenInfo;
        }
        tokenInfo.setValidityPeriod(expireTime);

//        Long issuedTime = (Long) responseJSON.get(OktaConstants.ACCESS_TOKEN_ISSUED);
//
//        if (issuedTime == null) {
//            tokenInfo.setTokenValid(false);
//            tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_ACCESS_TOKEN_EXPIRED);
//            return tokenInfo;
//        }
//        tokenInfo.setIssuedTime(issuedTime);

        String tokenScopes = (String) responseJSON.get(OktaConstants.ACCESS_TOKEN_SCOPE);

        if (tokenScopes != null && !tokenScopes.isEmpty()) {
            tokenInfo.setScope(tokenScopes.split("\\s+"));
        }

        tokenInfo.setTokenValid((Boolean) responseJSON.get(OktaConstants.ACCESS_TOKEN_ACTIVE));

        return tokenInfo;
    }
}