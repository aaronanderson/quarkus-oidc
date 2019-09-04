package com.github.quarkus.oidc.runtime.auth;

import java.util.Map;

import javax.inject.Inject;

import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.AuthenticationMechanismFactory;
import io.undertow.security.idm.IdentityManager;
import io.undertow.server.handlers.form.FormParserFactory;

public class OIDCAuthMechanismFactory implements AuthenticationMechanismFactory {

    @Inject
    private OIDCAuthContextInfo authContextInfo;

    public OIDCAuthMechanismFactory(OIDCAuthContextInfo authContextInfo) {
        this.authContextInfo = authContextInfo;
    }

    /**
     *
     * @param mechanismName - the login-config/auth-method, which will be OIDC
     * @param formParserFactory - unused form type of authentication factory
     * @param properties - the query parameters from the web.xml/login-config/auth-method value. 
     * @return the JWTAuthMechanism
     * @see JWTAuthContextInfo
     *
     */
    @Override
    public AuthenticationMechanism create(String mechanismName, IdentityManager identityManager, FormParserFactory formParserFactory, final Map<String, String> properties) {
        
        String realm = properties.get(REALM); 
        
        return new OIDCAuthMechanism(authContextInfo,formParserFactory, identityManager);
    }

}
