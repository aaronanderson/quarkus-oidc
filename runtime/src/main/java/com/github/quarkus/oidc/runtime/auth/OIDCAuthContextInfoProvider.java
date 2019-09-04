package com.github.quarkus.oidc.runtime.auth;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Singleton;

import io.quarkus.arc.DefaultBean;

@ApplicationScoped
public class OIDCAuthContextInfoProvider {

    private OIDCAuthContextInfo authContextInfo;

    public void initialize(OIDCAuthContextInfo authContextInfo) {
        this.authContextInfo = authContextInfo;
    }

    @Singleton
    @Produces
    @DefaultBean
    public OIDCAuthContextInfo authContextInfo() {
        return authContextInfo;
    }
}
