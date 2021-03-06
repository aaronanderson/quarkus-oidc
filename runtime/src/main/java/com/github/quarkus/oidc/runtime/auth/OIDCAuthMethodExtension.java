package com.github.quarkus.oidc.runtime.auth;

import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.enterprise.inject.spi.CDI;
import javax.inject.Inject;
import javax.servlet.ServletContext;
import javax.servlet.SessionTrackingMode;

import org.eclipse.microprofile.jwt.JsonWebToken;

import io.smallrye.jwt.auth.cdi.PrincipalProducer;
import io.undertow.security.api.AuthenticatedSessionManager;
import io.undertow.security.api.AuthenticatedSessionManager.AuthenticatedSession;
import io.undertow.security.idm.Account;
import io.undertow.server.HandlerWrapper;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.servlet.ServletExtension;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.ServletSessionConfig;

public class OIDCAuthMethodExtension implements ServletExtension {

	@Inject
	OIDCAuthContextInfo info;

	private String authMechanism;

	public String getAuthMechanism() {
		return authMechanism;
	}

	public void setAuthMechanism(String authMechanism) {
		this.authMechanism = authMechanism;
	}

	/**
	 * This registers the JWTAuthMechanismFactory under the "MP-JWT" mechanism name
	 *
	 * @param deploymentInfo - the deployment to augment
	 * @param servletContext - the ServletContext for the deployment
	 */
	@Override
	public void handleDeployment(DeploymentInfo deploymentInfo, ServletContext servletContext) {
		if (info.isSessionEnabled()) {
			// set session cookies to maintain JakartaEE session state between requests,
			// including authentication. OIDC interactive authentication implies web browser
			// activity where the browser will send
			// available cookies content requests.
			// deploymentInfo.setSessionPersistenceManager(new
			// InMemorySessionPersistence());
			deploymentInfo.setServletSessionConfig(new ServletSessionConfig().setSessionTrackingModes(Stream.of(SessionTrackingMode.COOKIE).collect(Collectors.toSet())));
			deploymentInfo.setDefaultSessionTimeout(info.getDefaultSessionTimeout());
			if (info.isSyncSessionExpiration()) {
				//invoked before authentication is assessed so that session can be cleared if the cached JWT token has expired 
				deploymentInfo.addSecurityWrapper(new SessionSyncWrapper());
			}
		}

		deploymentInfo.addInnerHandlerChainWrapper(new JWTHandlerWrapper());

		deploymentInfo.addSecurityConstraints(info.getSecurityConstraints());
		deploymentInfo.addAuthenticationMechanism(authMechanism, new OIDCAuthMechanismFactory(info));

	}

	class JWTHandlerWrapper implements HandlerWrapper {
		@Override
		public HttpHandler wrap(final HttpHandler handler) {
			return new HttpHandler() {
				@Override
				public void handleRequest(HttpServerExchange exchange) throws Exception {
					Account account = exchange.getSecurityContext().getAuthenticatedAccount();
					if (account != null && account.getPrincipal() instanceof JsonWebToken) {
						PrincipalProducer principalProducer = CDI.current().select(PrincipalProducer.class).get();
						principalProducer.setJsonWebToken((JsonWebToken) account.getPrincipal());
					}
					handler.handleRequest(exchange);
				}
			};
		}
	}

	class SessionSyncWrapper implements HandlerWrapper {
		@Override
		public HttpHandler wrap(final HttpHandler handler) {
			return new HttpHandler() {
				@Override
				public void handleRequest(HttpServerExchange exchange) throws Exception {
					AuthenticatedSessionManager sessionManager = exchange.getAttachment(AuthenticatedSessionManager.ATTACHMENT_KEY);
					if (sessionManager != null) {
						AuthenticatedSession authSession = sessionManager.lookupSession(exchange);
						if (authSession != null) {
							Account account = authSession.getAccount();
							if (account != null && account.getPrincipal() instanceof JsonWebToken) {
								JsonWebToken jwt = (JsonWebToken) account.getPrincipal();
								if (System.currentTimeMillis() > jwt.getExpirationTime() * 1000) {
									sessionManager.clearSession(exchange);
								}
							}
						}
					}

					handler.handleRequest(exchange);
				}
			};
		}
	}

}
