package com.github.quarkus.oidc.runtime;

import java.util.List;
import java.util.Map;

import io.quarkus.runtime.annotations.ConfigGroup;
import io.quarkus.runtime.annotations.ConfigItem;
import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;

@ConfigRoot(phase = ConfigPhase.BUILD_AND_RUN_TIME_FIXED)
public class OIDCConfiguration {

    /**
     * The authentication mechanism
     */
    @ConfigItem(defaultValue = "OIDC")
    public String authMechanism;

    /**
     * The authentication mechanism
     */
    @ConfigItem(defaultValue = "Quarkus-OIDC")
    public String realmName;

    /**
     * The OIDC configuration object
     */
    @ConfigItem(defaultValue = "true")
    public boolean enabled = true;

    /**
     * The the OIDC IDP issuer. Must be a URL that can return the OIDC /.well-known/openid-configuration metadata  
     */
    @ConfigItem
    public String issuer;

    /**
     * The OIDC OAuth ClientID
     */
    @ConfigItem
    public String clientId;

    /**
     * The OIDC OAuth ClientSecrect
     */
    @ConfigItem
    public String clientSecret;

    /**
     * The OIDC OAuth Scope
     */
    @ConfigItem(defaultValue = "openid profile groups")
    public String scope;

    /**
     * The OIDC claims
     */
    @ConfigItem
    public String claims;

    /**
     * The OIDC OAuth ResponseType
     */
    @ConfigItem(defaultValue = "id_token")
    public String responseType;

    /**
     * Clock Skew
     */
    @ConfigItem
    public int clockSkew = 30;

    /**
     * Use and verify the Nonce
     */
    @ConfigItem(defaultValue = "true")
    public boolean checkNonce = true;

    /**
     * OIDC redirect relative path back to this host
     */
    @ConfigItem(defaultValue = "/oidc")
    public String redirectPath;

    //@ConfigItem
    //private String issuer;

    /**
     * The name of the {@linkplain java.security.Provider} that supports SHA256withRSA signatures
     */
    @ConfigItem(defaultValue = "SunRsaSign")
    public String rsaSigProvider;

    /**
     * The name of the {@linkplain java.security.Provider} that supports AES encryption
     */
    @ConfigItem(defaultValue = "SunJCE")
    public String aesCryptProvider;

    /**
     * JWKS refresh interval
     */
    @ConfigItem(defaultValue = "0")
    public int jwksRefreshInterval;

    /**
     * Enable caching authentication in Servlet session and setting session cookie. If disabled JWT token is stored in a access_token cookie
     */
    @ConfigItem(defaultValue = "true")
    public boolean sessionEnabled;
    
    /**
     * Synchronize the authentication session with the JWT token expiration time
     */
    @ConfigItem(defaultValue = "false")
    public boolean syncSessionExpiration;
    
    
    /**
     * Default session timeout
     */
    @ConfigItem(defaultValue = "30")
    public int defaultSessionTimeout;

    /**
     * List of protected web resources 
     */
    @ConfigItem
    public Map<String, SecurityConstraintConfig> securityConstraints;

    @ConfigGroup
    public static class SecurityConstraintConfig {
        /**
         * The allowed roles
         */
        @ConfigItem
        List<String> roles;

        /**
         * The targeted web resource paths
         */
        @ConfigItem
        List<String> webResources;
    }

    /**
     * Include a default claim for testing purposes so that authentication can remain enabled without numerous OIDC authentication redirects. 
     */
    @ConfigItem
    public DefaultClaimConfig defaultClaims;

    @ConfigGroup
    public static class DefaultClaimConfig {

        /**
         * The DefaultClaim configuration object
         */
        @ConfigItem(defaultValue = "false")
        public boolean enabled = false;

        /**
         * The username of the JWT token
         */
        @ConfigItem(defaultValue = "test@acme.com")
        String subject;

        /**
         * groups to include in the JWT token.
         */
        @ConfigItem(defaultValue = "Everyone,Administrator")
        List<String> groups;

        /**
         * additional claims to be included
         */
        @ConfigItem
        Map<String, List<String>> claims;

    }

}
