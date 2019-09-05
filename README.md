## Overview

(Quarkus)[https://quarkus.io] is a flexible Java Microservices container that supports the (Eclipse Microprofile)[https://microprofile.io/] standard and can  be compiled to a native executable via (GRAALVM)[https://graalvm.org] for inclusion in a (Docker container)[https://www.docker.com/resources/what-container].   

OpenID Connect ([OIDC](http://openid.net/connect/)) is a ubiquitous standard for web browser and application authentication that use Json Web Tokens (JWT)[https://jwt.io/] for ID/access tokens.

Quarkus is mainly intended for building backend Microservices but it does include an embedded web server and is capable of serving static content such as single page applications (SPA)[https://en.wikipedia.org/wiki/Single-page_application]. While Quarkus support JWT token and (Keycloak)[https://quarkus.io/guides/keycloak-guide] authentication there is no way to directly interface with an OIDC compliant IDP like Okta. This extension extends the MP JWT token feature, plugs into the web server's security framework, and provides a way to secure all API and browser based access to Quarkus.

The best practice way of securing SPA's is to use a Javascript framework, for example (react-oidc)[https://www.npmjs.com/package/react-oidc], (AWS Amplify)[https://aws-amplify.github.io/docs/js/authentication], or (Okta OIDC JS)[https://github.com/okta/okta-oidc-js], to manage authentication locally in the browser application. The entire SPA is downloaded into the browser, the OIDC JavaScript library detects if the user requires authentication, redirects a user for OIDC authentication, captures the JWT token, and then includes it as an HTTP header to all backend server requests.

While this approach is extremely efficient for public facing applications it is not ideal for private proprietary application. It would be very easy for a competitor to monitor a web site for updates, download the entire SPA, and reverse engineer all of the page views and backend requests and expected responses without any authentication.

This extension solves this concern by enforcing authentication on all requests to protected resources in Quarkus.

## Session Management

In a classical secured web application a user is authenticated and a stateful session token is established. Since storing stateful session in a Microservices container instance goes against convention this extension offers two ways of handling sessions:

1. Java EE HTTP session - This is the default mode. Authentication is performed on the first resource request, upon successful authentication the principle is cached in memory, and a JSESSIONID cookie is set. Subsequent web requests include the cookie, the server confirms the cached session is valid, and reauthentication is bypassed and the requests is serviced. 

In this mode it is expected that a sticky load balancer be configured to ensure server affinity is available and requests from the same client go to the same Quarkus server. Hypothetically if the whole SPA is pushed to the client after authentication in a short duration of time the OIDC JWT token could be retrieved from Quarkus via a REST endpoint and then included in subsquent REST API invocations. This would allow the standard stateless MP JWT token authentication to be performed and no service disruption would take place if the original Quarkus server with the authentication session went offline.

2. JWT HTTP cookie - The JWT token is stored as an access_token cookie that is included in all requests. Standard MP-JWT token authentication can be performed for every request with retaining any session state.

Note that cookies are required for browser based authentication because by default browsers will automically include same domain cookies in all requests.

Finally this extensions extends the SmallRye JWT Quarkus extension so bearer JWT token authentication will still work if a token is present. 


## Configuration

# Maven

Include the Quarkus OIDC extension in the projects Maven POM file

`
<dependency>
			<groupId>com.github.quarkus.oidc</groupId>
			<artifactId>quarkus-oidc</artifactId>
			<version>2019.9.0-SNAPSHOT</version>
</dependency>
`

#application.properties

Here is an example configuration for the extension
`
quarkus.oidc.realm-name=oidc_okta
quarkus.oidc.security-constraints.1.roles=Everyone
quarkus.oidc.security-constraints.1.web-resources=/*



#External IDP 
#quarkus.oidc.issuer=https://someorg.okta.com
#quarkus.oidc.client-id=XXXXXXXXXXX 
#quarkus.oidc.client-secret=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX 
`

* quarkus.oidc.realm-name - label for the JavaEE security realm. In Quarkus this has little effect.

* quarkus.oidc.security-constraints.1.roles and quarkus.oidc.security-constraints.1.web-resources - One or more web constraint rules for securing protected web resources by role

* quarkus.oidc.issuer - OIDC issuer. This issuer should offer standard OIDC metadata at the /.well-known/openid-configuration path which will automatically be downloaded by this extension

* quarkus.oidc.client-id - The OIDC/OAuth 2.0 application client ID 

*quarkus.oidc.client-secret - The OIDC/OAuth 2.0 application client ID


There are a few other optional properties that can be configured:

* quarkus.oidc.enabled - set this to false to disable the extension

* quarkus.oidc.scope - Scope sent in OIDC/OAuth 2.0 authentication redirect. Default value is openid profile groups where the groups claim should contain the Java EE role names of the user.

* quarkus.oidc.claims - Optional JSON configuration of additional claims to request in the OIDC/OAuth 2.0 authentication request

* quarkus.oidc.redirect-path - /oidc by default - Location that the OIDC IDP should redirect the user after successful authentication that supports processing the OIDC/OAuth 2.0 created tokens.

When developing secure applications that require authentication the need to constantly reauthenticate when services are restarted is anoying and counterproductive. This extension allows for configuring default JWT credentials for test purposes only so that authentication can remain enabled without requiring manual login. The configuration below enables this feature:

`
#Default JWT for local testing
quarkus.oidc.default-claims.enabled=true
quarkus.oidc.default-claims.subject=test@quarkus.io 
quarkus.oidc.default-claims.groups=Everyone,Administrator
quarkus.oidc.default-claims.claims.test=test
`

Set quarkus.oidc.default-claims.enabled to true to enabled this feature. Adjust the groups to match the application roles accordingly. The Quarkus environment profiles can be used to enable this feature during local development. For instance prefix these properties with %dev. and specify a profile during startup i.e. 


`
%dev.quarkus.oidc.default-claims.enabled=true
%dev.quarkus.oidc.default-claims.subject=test@quarkus.io 
%dev.quarkus.oidc.default-claims.groups=Everyone,Administrator
%dev.quarkus.oidc.default-claims.claims.test=test

`

`mvn complie quarkus:dev -Dquarkus.profile=dev`