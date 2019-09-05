package com.github.quarkus.oidc.runtime;

import java.io.InputStream;
import java.net.URI;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.jboss.logging.Logger;
import org.wildfly.security.auth.realm.token.TokenSecurityRealm;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityRealm;

import com.github.quarkus.oidc.runtime.OIDCConfiguration.SecurityConstraintConfig;
import com.github.quarkus.oidc.runtime.auth.OIDCAuthContextInfo;
import com.github.quarkus.oidc.runtime.auth.OIDCAuthMethodExtension;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderConfigurationRequest;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

import io.quarkus.arc.runtime.BeanContainer;
import io.quarkus.runtime.RuntimeValue;
import io.quarkus.runtime.annotations.Recorder;
import io.quarkus.smallrye.jwt.runtime.auth.ElytronJwtCallerPrincipal;
import io.quarkus.smallrye.jwt.runtime.auth.JwtIdentityManager;
import io.quarkus.smallrye.jwt.runtime.auth.MpJwtValidator;
import io.undertow.security.idm.IdentityManager;
import io.undertow.servlet.ServletExtension;
import io.undertow.servlet.api.SecurityConstraint;
import io.undertow.servlet.api.WebResourceCollection;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

@Recorder
public class OIDCRecorder {

    private static final Logger log = Logger.getLogger(OIDCRecorder.class.getName());

    public static final String DEFAULT_CLAIM_ISSUER = "https://quarkus-oidc.com";

    /**
     * Create the JwtIdentityManager
     * 
     * @param securityDomain - the SecurityDomain to use for auth decisions
     * @return - the IdentityManager instance to register
     */
    public IdentityManager createIdentityManager(RuntimeValue<SecurityDomain> securityDomain) {
        return new JwtIdentityManager(securityDomain.getValue());
    }

    /**
     * Create the JWTAuthMethodExtension servlet extension
     * 
     * @param authMechanism - name to use for MP-JWT auth mechanism
     * @param container - bean container to create JWTAuthMethodExtension bean
     * @return JWTAuthMethodExtension
     */
    public ServletExtension createAuthExtension(String authMechanism, BeanContainer container) {
        OIDCAuthMethodExtension authExt = container.instance(OIDCAuthMethodExtension.class);
        authExt.setAuthMechanism(authMechanism);
        return authExt;
    }

    public void staticInitAuthContextInfo(BeanContainer container, OIDCConfiguration config) throws Exception {
        OIDCAuthContextInfo authContextInfo = container.instance(OIDCAuthContextInfo.class);
        authContextInfo.setAuthMechanism(config.authMechanism);
        authContextInfo.setRedirectPath(config.redirectPath);
        authContextInfo.setSessionEnabled(config.sessionEnabled);
        authContextInfo.setSyncSessionExpiration(config.syncSessionExpiration);
        authContextInfo.setDefaultSessionTimeout(config.defaultSessionTimeout);

        authContextInfo.setSecurityConstraints(new ArrayList<>(config.securityConstraints.size()));
        for (Map.Entry<String, SecurityConstraintConfig> securityConfig : config.securityConstraints.entrySet()) {
            SecurityConstraint constraint = new SecurityConstraint();
            for (String role : securityConfig.getValue().roles) {
                constraint.addRoleAllowed(role);
            }

            WebResourceCollection webResourceCollection = new WebResourceCollection();
            for (String webResource : securityConfig.getValue().webResources) {
                //TODO support method
                webResourceCollection.addUrlPattern(webResource);
            }

            constraint.addWebResourceCollection(webResourceCollection);
            authContextInfo.getSecurityConstraints().add(constraint);
        }

    }

    public void runtimeInitAuthContextInfo(BeanContainer container, OIDCConfiguration config) throws Exception {
        OIDCAuthContextInfo authContextInfo = container.instance(OIDCAuthContextInfo.class);

        if (config.defaultClaims.enabled) {
            JSONArray claimGroups = new JSONArray();
            claimGroups.addAll(config.defaultClaims.groups);
            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder().subject(config.defaultClaims.subject).claim("preferred_username", config.defaultClaims.subject).issuer(DEFAULT_CLAIM_ISSUER).expirationTime(new Date(new Date().getTime() + (60 * 1000) * (60 * 10))).claim("groups", claimGroups);
            if (config.defaultClaims.claims != null) {
                for (Map.Entry<String, List<String>> entry : config.defaultClaims.claims.entrySet()) {
                    if (entry.getValue().size() == 1) {
                        claimsBuilder.claim(entry.getKey(), entry.getValue().get(0));
                    } else {
                        claimsBuilder.claim(entry.getKey(), entry.getValue());
                    }
                }
            }
            RSAKey rsaJWK = new RSAKeyGenerator(2048).keyID("QuarkusOIDCEmbedded").generate();
            RSAKey rsaPublicJWK = rsaJWK.toPublicJWK();
            JWSSigner signer = new RSASSASigner(rsaJWK);
            SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(), claimsBuilder.build());
            signedJWT.sign(signer);
            authContextInfo.setDefaultJWT(signedJWT.serialize());

            authContextInfo.setIssuer(new Issuer(DEFAULT_CLAIM_ISSUER));
            authContextInfo.setIssuedBy(DEFAULT_CLAIM_ISSUER);
            authContextInfo.setPublicKeyLocation(null);
            authContextInfo.setSignerKey(rsaPublicJWK.toRSAPublicKey());

        } else {

            if (config.issuer == null || config.issuer.isEmpty()) {
                throw new Exception("issuer configuration is required");
            }
            if (config.clientId == null || config.clientId.isEmpty()) {
                throw new Exception("clientId configuration is required");
            }

            if (config.clientSecret == null || config.clientSecret.isEmpty()) {
                throw new Exception("clientSecret configuration is required");
            }

            authContextInfo.setClientId(new ClientID(config.clientId));
            Secret secret = new Secret(config.clientSecret);

            log.infof("Loading OIDC configuration for realm %s from issuer %s", config.realmName, config.issuer);

            OIDCProviderConfigurationRequest request = new OIDCProviderConfigurationRequest(new Issuer(config.issuer));
            HTTPRequest httpRequest = request.toHTTPRequest();
            HTTPResponse httpResponse = httpRequest.send();
            OIDCProviderMetadata providerMetadata = OIDCProviderMetadata.parse(httpResponse.getContentAsJSONObject());

            authContextInfo.setIssuer(new Issuer(providerMetadata.getIssuer()));
            authContextInfo.setIssuedBy(providerMetadata.getIssuer().getValue());
            authContextInfo.setAuthURI(providerMetadata.getAuthorizationEndpointURI());
            authContextInfo.setTokenURI(providerMetadata.getTokenEndpointURI());
            authContextInfo.setUserInfoURI(providerMetadata.getUserInfoEndpointURI());
            authContextInfo.setRsaKeys(getProviderRSAKeys(providerMetadata.getJWKSetURI()));

            authContextInfo.setPublicKeyLocation(providerMetadata.getJWKSetURI().toString());

            if (authContextInfo.getRsaKeys() != null) {
                authContextInfo.setRsaTokenValidator(new IDTokenValidator(authContextInfo.getIssuer(), authContextInfo.getClientId(), JWSAlgorithm.RS256, authContextInfo.getRsaKeys()));
                authContextInfo.getRsaTokenValidator().setMaxClockSkew(config.clockSkew);

            }

            authContextInfo.setHmacTokenValidator(new IDTokenValidator(authContextInfo.getIssuer(), authContextInfo.getClientId(), JWSAlgorithm.HS256, secret));
            authContextInfo.getHmacTokenValidator().setMaxClockSkew(config.clockSkew);

            authContextInfo.setExpGracePeriodSecs(config.clockSkew);
            authContextInfo.setJwksRefreshInterval(config.jwksRefreshInterval);

            authContextInfo.setResponseType(new ResponseType(config.responseType));
            authContextInfo.setScope(Scope.parse(config.scope));

            if (config.claims != null && !config.claims.isEmpty()) {
                authContextInfo.setClaims(ClaimsRequest.parse(config.claims));
            }

            authContextInfo.setAesCryptProvider(config.aesCryptProvider);
            authContextInfo.setStateKey(stateKey(config));

        }

    }

    private JWKSet getProviderRSAKeys(URI jwkSetURI) throws Exception {
        try {
            InputStream is = jwkSetURI.toURL().openStream();
            String jsonString = IOUtils.readInputStreamToString(is, Charset.defaultCharset());
            return getProviderRSAKeys(JSONObjectUtils.parse(jsonString));
        } catch (Exception e) {
            return null;
        }

    }

    JWKSet getProviderRSAKeys(JSONObject json) throws ParseException {
        JSONArray keyList = (JSONArray) json.get("keys");
        List<JWK> rsaKeys = new LinkedList<>();
        for (Object key : keyList) {
            JSONObject k = (JSONObject) key;
            if (k.get("use").equals("sig") && k.get("kty").equals("RSA")) {
                rsaKeys.add(RSAKey.parse(k));
            }
        }
        if (!rsaKeys.isEmpty()) {
            return new JWKSet(rsaKeys);
        }
        throw new IllegalArgumentException("No RSA keys found");
    }

    protected SecretKey stateKey(OIDCConfiguration config) {
        // only generate the state encryption key if the HTTP session is going 
        // to be used for nonance checking as well. 
        if (config.checkNonce) {
            try {
                if (config.clientSecret != null && !config.clientSecret.isEmpty()) {
                    byte[] key = config.clientSecret.getBytes("UTF-8");
                    MessageDigest sha = MessageDigest.getInstance("SHA-1");
                    key = sha.digest(key);
                    key = Arrays.copyOf(key, 16);
                    SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
                    return secretKeySpec;
                } else {
                    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
                    keyGenerator.init(128);
                    return keyGenerator.generateKey();
                }

            } catch (Exception e) {
                log.error("stateKey error", e);

            }
        }
        return null;
    }

    /**
     * Create the TokenSecurityRealm
     * 
     * @return runtime wrapped TokenSecurityRealm
     */
    public RuntimeValue<SecurityRealm> createTokenRealm(BeanContainer container) {
        MpJwtValidator jwtValidator = container.instance(MpJwtValidator.class);
        TokenSecurityRealm tokenRealm = TokenSecurityRealm.builder().claimToPrincipal(claims -> new ElytronJwtCallerPrincipal(claims)).validator(jwtValidator).build();
        return new RuntimeValue<>(tokenRealm);
    }

}
