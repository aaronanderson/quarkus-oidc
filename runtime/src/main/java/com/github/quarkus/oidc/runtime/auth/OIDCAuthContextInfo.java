package com.github.quarkus.oidc.runtime.auth;

import java.net.URI;
import java.util.List;

import javax.crypto.SecretKey;
import javax.enterprise.context.ApplicationScoped;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.undertow.servlet.api.SecurityConstraint;

@ApplicationScoped
public class OIDCAuthContextInfo extends JWTAuthContextInfo {

    private ClientID clientId;
    private Issuer issuer;
    private URI authURI;
    private URI tokenURI;
    private URI userInfoURI;
    private JWKSet rsaKeys;
    private Scope scope;
    private ClaimsRequest claims;
    private ResponseType responseType;
    private boolean checkNonce;
    private String aesCryptProvider;
    private SecretKey stateKey;
    private IDTokenValidator rsaTokenValidator;
    private IDTokenValidator hmacTokenValidator;
    private String authMechanism;
    private String redirectPath;
    private boolean sessionEnabled;
    private List<SecurityConstraint> securityConstraints;

    private String defaultJWT;

    public ClientID getClientId() {
        return clientId;
    }

    public void setClientId(ClientID clientId) {
        this.clientId = clientId;
    }

    public Issuer getIssuer() {
        return issuer;
    }

    public void setIssuer(Issuer issuer) {
        this.issuer = issuer;
    }

    public URI getAuthURI() {
        return authURI;
    }

    public void setAuthURI(URI authURI) {
        this.authURI = authURI;
    }

    public URI getTokenURI() {
        return tokenURI;
    }

    public void setTokenURI(URI tokenURI) {
        this.tokenURI = tokenURI;
    }

    public URI getUserInfoURI() {
        return userInfoURI;
    }

    public void setUserInfoURI(URI userInfoURI) {
        this.userInfoURI = userInfoURI;
    }

    public JWKSet getRsaKeys() {
        return rsaKeys;
    }

    public void setRsaKeys(JWKSet rsaKeys) {
        this.rsaKeys = rsaKeys;
    }

    public Scope getScope() {
        return scope;
    }

    public void setScope(Scope scope) {
        this.scope = scope;
    }

    public ClaimsRequest getClaims() {
        return claims;
    }

    public void setClaims(ClaimsRequest claims) {
        this.claims = claims;
    }

    public ResponseType getResponseType() {
        return responseType;
    }

    public void setResponseType(ResponseType responseType) {
        this.responseType = responseType;
    }

    public boolean isCheckNonce() {
        return checkNonce;
    }

    public void setCheckNonce(boolean checkNonce) {
        this.checkNonce = checkNonce;
    }

    public String getAesCryptProvider() {
        return aesCryptProvider;
    }

    public void setAesCryptProvider(String aesCryptProvider) {
        this.aesCryptProvider = aesCryptProvider;
    }

    public SecretKey getStateKey() {
        return stateKey;
    }

    public void setStateKey(SecretKey stateKey) {
        this.stateKey = stateKey;
    }

    public IDTokenValidator getRsaTokenValidator() {
        return rsaTokenValidator;
    }

    public void setRsaTokenValidator(IDTokenValidator rsaTokenValidator) {
        this.rsaTokenValidator = rsaTokenValidator;
    }

    public IDTokenValidator getHmacTokenValidator() {
        return hmacTokenValidator;
    }

    public void setHmacTokenValidator(IDTokenValidator hmacTokenValidator) {
        this.hmacTokenValidator = hmacTokenValidator;
    }

    public String getAuthMechanism() {
        return authMechanism;
    }

    public void setAuthMechanism(String authMechanism) {
        this.authMechanism = authMechanism;
    }

    public String getRedirectPath() {
        return redirectPath;
    }

    public void setRedirectPath(String redirectPath) {
        this.redirectPath = redirectPath;
    }

    public boolean isSessionEnabled() {
        return sessionEnabled;
    }

    public void setSessionEnabled(boolean sessionEnabled) {
        this.sessionEnabled = sessionEnabled;
    }

    public String getDefaultJWT() {
        return defaultJWT;
    }

    public void setDefaultJWT(String defaultJWT) {
        this.defaultJWT = defaultJWT;
    }

    public List<SecurityConstraint> getSecurityConstraints() {
        return securityConstraints;
    }

    public void setSecurityConstraints(List<SecurityConstraint> securityConstraints) {
        this.securityConstraints = securityConstraints;
    }
    
    

}
