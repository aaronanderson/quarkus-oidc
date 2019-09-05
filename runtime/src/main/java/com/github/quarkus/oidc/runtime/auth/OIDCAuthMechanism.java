package com.github.quarkus.oidc.runtime.auth;

import java.net.URI;
import java.security.AccessController;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.crypto.Cipher;
import javax.enterprise.inject.spi.CDI;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.logging.Logger;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Display;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.Prompt;

import io.quarkus.smallrye.jwt.runtime.auth.JWTCredential;
import io.smallrye.jwt.auth.AbstractBearerTokenExtractor;
import io.smallrye.jwt.auth.cdi.PrincipalProducer;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.undertow.UndertowLogger;
import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.SecurityContext;
import io.undertow.security.idm.Account;
import io.undertow.security.idm.IdentityManager;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.Cookie;
import io.undertow.server.handlers.CookieImpl;
import io.undertow.server.handlers.form.FormData;
import io.undertow.server.handlers.form.FormParserFactory;
import io.undertow.server.session.Session;
import io.undertow.servlet.handlers.ServletRequestContext;
import io.undertow.servlet.spec.HttpSessionImpl;
import io.undertow.util.AttachmentKey;
import io.undertow.util.Headers;
import io.undertow.util.Methods;
import io.undertow.util.RedirectBuilder;
import io.undertow.util.StatusCodes;

public class OIDCAuthMechanism implements AuthenticationMechanism {

    private static final String NONCE_KEY = "com.github.quarkus.oidc.auth.nonce";
    private static final String LOCATION_KEY = "com.github.quarkus.oidc.auth.location";

    private static final String OIDC_JWT_COOKIE_NAME = "access_token";

    private static final Logger log = Logger.getLogger(OIDCAuthMechanism.class.getName());

    private OIDCAuthContextInfo authContextInfo;
    private FormParserFactory formParserFactory;
    private IdentityManager identityManager;

    public OIDCAuthMechanism(OIDCAuthContextInfo authContextInfo, FormParserFactory formParserFactory, IdentityManager identityManager) {
        this.authContextInfo = authContextInfo;
        this.formParserFactory = formParserFactory;
        this.identityManager = identityManager;
    }

    /**
     * Extract the Authorization header and validate the bearer token if it exists. If it does, and is validated, this
     * builds the org.jboss.security.SecurityContext authenticated Subject that drives the container APIs as well as
     * the authorization layers.
     *
     * @param exchange - the http request exchange object
     * @param securityContext - the current security context that
     * @return one of AUTHENTICATED, NOT_AUTHENTICATED or NOT_ATTEMPTED depending on the header and authentication outcome.
     */
    @Override
    public AuthenticationMechanismOutcome authenticate(HttpServerExchange exchange, SecurityContext securityContext) {

        OIDCContext context = new OIDCContext();
        context.setError(false);
        exchange.putAttachment(OIDCContext.ATTACHMENT_KEY, context);

        log.debugf("Requested URL: %s", exchange.getRelativePath());

        // Only authenticate if required. For example, if no auth-constraint is specified 
        // for a security-constraint in the web.xml unauthenticated access should be allowed. 
        if (!securityContext.isAuthenticationRequired()) {
            return AuthenticationMechanismOutcome.NOT_ATTEMPTED;
        }

        if (authContextInfo.getDefaultJWT() != null) {
            return processJWTToken(authContextInfo.getDefaultJWT(), false, null, exchange);
        }

        //Delegate to Quarkus Microprofile JWT authentication if JWT token is present 
        String jwtToken = new JWTUndertowBearerTokenExtractor(authContextInfo, exchange).getBearerToken();
        if (jwtToken == null) {
            jwtToken = Optional.ofNullable(exchange.getRequestCookies().get(OIDC_JWT_COOKIE_NAME)).map(t -> t.getValue()).orElse(null);
        }
        if (jwtToken != null) {
            return processJWTToken(jwtToken, false, null, exchange);
        }

        //Process requests for OIDC OAuth response redirects
        if (exchange.getRequestPath().equals(authContextInfo.getRedirectPath())) {
            return processOIDCAuthResponse(exchange);
        }

        // for identity provider initiated login, capture the issuer. If IDP  pointed at OIDC endpoint above authenticated users would bypass this module 
        // and the request would go to the protected application. More than likely the application would not have anything mapped at the OIDC endpoint URL
        //and an error would be generated. 
        if (exchange.getQueryParameters().containsKey("iss")) {
            context.setIssuer(exchange.getQueryParameters().get("iss").getLast());
        }

        return AuthenticationMechanismOutcome.NOT_ATTEMPTED;

    }

    @Override
    public ChallengeResult sendChallenge(HttpServerExchange exchange, SecurityContext securityContext) {
        OIDCContext oidcContext = exchange.getAttachment(OIDCContext.ATTACHMENT_KEY);
        // NOT_AUTHENTICATED and NOT_ATTEMPTED always send challenges 
        if (oidcContext.isError()) {
            return new ChallengeResult(false, StatusCodes.UNAUTHORIZED);
        }

        //exchange.getResponseHeaders().put(WWW_AUTHENTICATE, "Bearer {token}");

        String redirectURL = buildAuthorizationURL(exchange);
        log.debugf("Challenge redirect: %s", redirectURL);
        exchange.getResponseHeaders().put(Headers.LOCATION, redirectURL);
        return new ChallengeResult(true, StatusCodes.FOUND);
    }

    protected AuthenticationMechanismOutcome processJWTToken(String jwtToken, boolean redirect, String redirectURL, HttpServerExchange exchange) {
        //String authorization = exchange.getRequestHeaders().getFirst(Headers.AUTHORIZATION);
        try {
            try {
                JWTCredential credential = new JWTCredential(jwtToken, null);

                log.debugf("Bearer token: %s", jwtToken);

                // Install the JWT principal as the caller
                Account account = identityManager.verify(credential.getName(), credential);
                if (account != null) {                    
                    //set cachingRequired to set authentication in session cookie
                    boolean cachingRequired = authContextInfo.isSessionEnabled();
                    exchange.getSecurityContext().authenticationComplete(account, authContextInfo.getAuthMechanism(), cachingRequired);
                    log.debugf("Authenticated caller(%s) for path(%s) with roles: %s", credential.getName(), exchange.getRequestPath(), account.getRoles());
                    if (!authContextInfo.isSessionEnabled() && !exchange.getRequestCookies().containsKey(OIDC_JWT_COOKIE_NAME)) {
                        setJWTCookie(exchange, jwtToken);
                    }
                    if (redirect) {
                        exchange.getResponseHeaders().put(Headers.LOCATION, redirectURL != null && !redirectURL.isEmpty() ? redirectURL : getContextPath(exchange));
                        exchange.setStatusCode(StatusCodes.FOUND);
                        exchange.endExchange();
                    }

                    return AuthenticationMechanismOutcome.AUTHENTICATED;
                } else {
                    UndertowLogger.SECURITY_LOGGER.info("Failed to authenticate JWT bearer token");
                    return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
                }
            } catch (Exception e) {
                UndertowLogger.SECURITY_LOGGER.infof(e, "Failed to validate JWT bearer token");
                return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
            }
        } catch (Exception e) {
            OIDCContext oidcContext = exchange.getAttachment(OIDCContext.ATTACHMENT_KEY);
            oidcContext.setError(true);
            exchange.getSecurityContext().authenticationFailed("Unable to obtain OIDC JWT token from authorization header", authContextInfo.getAuthMechanism());
            return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
        }

    }

    protected String getContextPath(HttpServerExchange exchange) {
        final ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        return servletRequestContext.getCurrentServletContext().getContextPath();
    }

    protected void setJWTCookie(HttpServerExchange exchange, String jwtToken) {
        //needed for local testing 
        String domain = exchange.getHostName();
        if ("localhost".equals(domain)) {
            domain = null;
        }
        boolean secure = "https".equals(exchange.getRequestScheme());
        final ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        //ideally the cookie timeout would be tuned to JWT expiration time but it wouldn't be worth parsing it just for that one value
        exchange.getResponseCookies().put(OIDC_JWT_COOKIE_NAME, new CookieImpl(OIDC_JWT_COOKIE_NAME).setMaxAge(servletRequestContext.getCurrentServletContext().getSessionTimeout()).setHttpOnly(false).setSecure(secure).setDomain(domain).setPath(getContextPath(exchange)).setValue(jwtToken));
    }

    protected AuthenticationMechanismOutcome processOIDCAuthResponse(HttpServerExchange exchange) {
        try {

            AuthenticationResponse authResp = parseAuthenticationResponse(exchange);

            if (authResp instanceof AuthenticationErrorResponse) {
                ErrorObject error = ((AuthenticationErrorResponse) authResp).getErrorObject();
                throw new IllegalStateException(String.format("OIDC Authentication error: code %s description: %s", error.getCode(), error.getDescription()));
            }

            AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse) authResp;

            // could store returnURL/state 
            // in session but state is encrypted 
            State state = successResponse.getState();

            AuthorizationCode authCode = successResponse.getAuthorizationCode();
            JWT idToken = successResponse.getIDToken();
            AccessToken accessToken = successResponse.getAccessToken();

            if (idToken == null && authCode != null) {
                OIDCTokenResponse tokenResponse = fetchToken(authCode, exchange);
                idToken = tokenResponse.getOIDCTokens().getIDToken();
                accessToken = tokenResponse.getOIDCTokens().getAccessToken();
            }
            //delegate to undertow security to validate the JWT            
            String returnURL = restoreState(state != null ? state.getValue() : null, exchange);

            return processJWTToken(idToken.serialize(), true, returnURL, exchange);

        } catch (Exception e) {
            log.error("OIDC authentication response error", e);
            OIDCContext oidcContext = exchange.getAttachment(OIDCContext.ATTACHMENT_KEY);
            oidcContext.setError(true);
            exchange.getSecurityContext().authenticationFailed("OIDC auth response processing failed", authContextInfo.getAuthMechanism());
            return AuthenticationMechanismOutcome.NOT_ATTEMPTED;
        }

    }

    protected OIDCTokenResponse fetchToken(AuthorizationCode authCode, HttpServerExchange exchange) throws Exception {
        URI redirectURI = new URI(RedirectBuilder.redirect(exchange, authContextInfo.getRedirectPath()));
        TokenRequest tokenReq = new TokenRequest(authContextInfo.getTokenURI(), authContextInfo.getClientId(), new AuthorizationCodeGrant(authCode, redirectURI));
        HTTPResponse tokenHTTPResp = tokenReq.toHTTPRequest().send();
        TokenResponse tokenResponse = OIDCTokenResponseParser.parse(tokenHTTPResp);
        if (tokenResponse instanceof TokenErrorResponse) {
            ErrorObject error = ((TokenErrorResponse) tokenResponse).getErrorObject();
            throw new IllegalStateException(String.format("OIDC TokenRequest error: code %s description: %s", error.getCode(), error.getDescription()));
        }
        return (OIDCTokenResponse) tokenResponse;
    }

    protected AuthenticationResponse parseAuthenticationResponse(HttpServerExchange exchange) throws Exception {
        Map<String, List<String>> params = new HashMap<>();
        exchange.getQueryParameters().forEach((k, v) -> {
            params.put(k, new ArrayList<String>(v));
        });
        if (exchange.getRequestMethod().equals(Methods.POST)) {
            FormData formData = formParserFactory.createParser(exchange).parseBlocking();
            formData.forEach(p -> {
                params.put(p, Stream.of(formData.getFirst(p).getValue()).collect(Collectors.toList()));
            });
        }
        return AuthenticationResponseParser.parse(new URI(exchange.getRequestURI()), params);
    }

    private String buildAuthorizationURL(HttpServerExchange exchange) {

        try {
            //ClientID clientId = new ClientID(oidcProvider.getClientId()); 

            ResponseMode responseMode = ResponseMode.FORM_POST;
            Prompt prompt = new Prompt(Prompt.Type.LOGIN);
            Display display = Display.PAGE;

            //if proxy scheme needs to be preserved, i.e. TLS terminator is used and WildFly receives http requests, use the have the proxy set the host and X-Forwarded-Proto header and use the   
            //swarm:undertow:servers:default-server:http-listeners:default:proxy-address-forwarding: true setting to allow WildFly to write the correct scheme   
            String redirectURL = RedirectBuilder.redirect(exchange, authContextInfo.getRedirectPath(), false);
            URI redirectURI = new URI(redirectURL);
            String returnURL = null;
            if (!exchange.getRequestPath().equals(authContextInfo.getRedirectPath())) {
                returnURL = RedirectBuilder.redirect(exchange, exchange.getRequestURI());
            } else {
                returnURL = RedirectBuilder.redirect(exchange, getContextPath(exchange), false);
            }

            String stateValue = persistState(returnURL, exchange);
            State state = stateValue != null ? new State(stateValue) : new State();
            Nonce nonce = new Nonce();
            if (authContextInfo.isCheckNonce()) {
                getSession(exchange).setAttribute(NONCE_KEY, nonce.getValue());
            }
            AuthenticationRequest.Builder builder = new AuthenticationRequest.Builder(authContextInfo.getResponseType(), authContextInfo.getScope(), authContextInfo.getClientId(), redirectURI);
            builder.endpointURI(authContextInfo.getAuthURI()).responseMode(responseMode).state(state).nonce(nonce).display(display).prompt(prompt).maxAge(-1).claims(authContextInfo.getClaims());
            //AuthenticationRequest authRequest = new AuthenticationRequest(authContextInfo.getAuthURI(), authContextInfo.getResponseType(), responseMode, authContextInfo.getScope(), authContextInfo.getClientId(), redirectURI, state, nonce, display, prompt, -1, null, null, null, null, null, authContextInfo.getClaims(), null, null, null, null);
            return builder.build().toURI().toString();
        } catch (Exception e) {
            log.error("authorization URL build error", e);
            return null;
        }

    }

    protected String persistState(String state, HttpServerExchange exchange) throws Exception {
        // if NoOnce is checked based on session value restore redirect URL the 
        // same way 
        if (authContextInfo.isCheckNonce()) {
            getSession(exchange).setAttribute(LOCATION_KEY, state);
            return state;
        } else {
            Cipher cipher = Cipher.getInstance("AES");//, authContextInfo.getAesCryptProvider());
            cipher.init(Cipher.ENCRYPT_MODE, authContextInfo.getStateKey());
            byte[] secureReturnURL = cipher.doFinal(state.getBytes());
            return Base64.getEncoder().encodeToString(secureReturnURL);
        }
    }

    protected String restoreState(String state, HttpServerExchange exchange) throws Exception {
        if (authContextInfo.isCheckNonce()) {
            String previousState = (String) getSession(exchange).getAttribute(LOCATION_KEY);
            return previousState != null && previousState.equals(state) ? state : null;
        } else {
            byte[] secureReturnURL = Base64.getDecoder().decode(state);
            Cipher cipher = Cipher.getInstance("AES");//, authContextInfo.getAesCryptProvider());
            cipher.init(Cipher.DECRYPT_MODE, authContextInfo.getStateKey());
            try {
                secureReturnURL = cipher.doFinal(secureReturnURL);
                return new String(secureReturnURL);
            } catch (Exception e) {
                // non-critical exception 
                log.trace("State decryption failed", e);
                return null;
            }
        }
    }

    protected Session getSession(HttpServerExchange exchange) {
        final ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        HttpSessionImpl httpSession = servletRequestContext.getCurrentServletContext().getSession(exchange, true);
        Session session;
        if (System.getSecurityManager() == null) {
            session = httpSession.getSession();
        } else {
            session = AccessController.doPrivileged(new HttpSessionImpl.UnwrapSessionAction(httpSession));
        }
        return session;
    }

    private static class JWTUndertowBearerTokenExtractor extends AbstractBearerTokenExtractor {
        private HttpServerExchange httpExchange;

        JWTUndertowBearerTokenExtractor(JWTAuthContextInfo authContextInfo, HttpServerExchange exchange) {
            super(authContextInfo);
            this.httpExchange = exchange;
        }

        @Override
        protected String getHeaderValue(String headerName) {
            return httpExchange.getRequestHeaders().getFirst(headerName);
        }

        @Override
        protected String getCookieValue(String cookieName) {
            Cookie cookie = httpExchange.getRequestCookies().get(cookieName);
            return cookie != null ? cookie.getValue() : null;
        }
    }

    public static class OIDCContext {

        static final AttachmentKey<OIDCContext> ATTACHMENT_KEY = AttachmentKey.create(OIDCContext.class);

        private boolean error;
        private String issuer;

        public boolean isError() {
            return error;
        }

        public void setError(boolean error) {
            this.error = error;
        }

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

    }
}
