package com.github.quarkus.oidc.deployment;

import org.glassfish.json.JsonProviderImpl;
import org.jboss.logging.Logger;
import org.wildfly.security.auth.server.SecurityRealm;

import com.github.quarkus.oidc.runtime.OIDCConfiguration;
import com.github.quarkus.oidc.runtime.OIDCRecorder;
import com.github.quarkus.oidc.runtime.auth.OIDCAuthContextInfo;
import com.github.quarkus.oidc.runtime.auth.OIDCAuthMethodExtension;

import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.arc.deployment.BeanContainerBuildItem;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.ExtensionSslNativeSupportBuildItem;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.deployment.builditem.ObjectSubstitutionBuildItem;
import io.quarkus.deployment.builditem.substrate.ReflectiveClassBuildItem;
import io.quarkus.elytron.security.deployment.AuthConfigBuildItem;
import io.quarkus.elytron.security.deployment.IdentityManagerBuildItem;
import io.quarkus.elytron.security.deployment.JCAProviderBuildItem;
import io.quarkus.elytron.security.deployment.SecurityDomainBuildItem;
import io.quarkus.elytron.security.deployment.SecurityRealmBuildItem;
import io.quarkus.elytron.security.runtime.AuthConfig;
import io.quarkus.runtime.RuntimeValue;
import io.quarkus.smallrye.jwt.runtime.auth.ClaimAttributes;
import io.quarkus.smallrye.jwt.runtime.auth.ElytronJwtCallerPrincipal;
import io.quarkus.smallrye.jwt.runtime.auth.MpJwtValidator;
import io.quarkus.undertow.deployment.ServletExtensionBuildItem;
import io.smallrye.jwt.auth.cdi.PrincipalProducer;
import io.undertow.security.idm.IdentityManager;
import io.undertow.servlet.ServletExtension;

class QuarkusOIDCProcessor {

	private static final Logger log = Logger.getLogger(QuarkusOIDCProcessor.class.getName());

	OIDCConfiguration config;

	private static final String FEATURE = "oidc";

	@BuildStep
	FeatureBuildItem feature() {
		return new FeatureBuildItem(FEATURE);
	}

	//    @BuildStep
	//    SubstrateConfigBuildItem disableKeepAlive() {
	//        return new SubstrateConfigBuildItem.Builder().addNativeImageSystemProperty("http.keepAlive", "false").build();
	//    }

	//    @BuildStep
	//    void registerRuntimeInitializations(BuildProducer<RuntimeInitializedClassBuildItem> runtimeInitializer) {
	//        runtimeInitializer.produce(new RuntimeInitializedClassBuildItem("sun.security.ssl.SSLContextImpl"));
	//    }

	@BuildStep
	void registerAdditionalBeans(BuildProducer<AdditionalBeanBuildItem> additionalBeans) {
		AdditionalBeanBuildItem.Builder unremovable = AdditionalBeanBuildItem.builder().setUnremovable();
		unremovable.addBeanClass(MpJwtValidator.class);
		unremovable.addBeanClass(OIDCAuthMethodExtension.class);
		unremovable.addBeanClass(PrincipalProducer.class);
		additionalBeans.produce(unremovable.build());
		AdditionalBeanBuildItem.Builder removable = AdditionalBeanBuildItem.builder();
		removable.addBeanClass(OIDCAuthContextInfo.class);

		additionalBeans.produce(removable.build());
	}

	@BuildStep
	@Record(ExecutionTime.STATIC_INIT)
	ExtensionSslNativeSupportBuildItem sslNative() {
		return new ExtensionSslNativeSupportBuildItem(FEATURE);

	}

	/**
	* Configure a TokenSecurityRealm if enabled
	*
	* @param recorder - jwt runtime recorder
	* @param securityRealm - producer used to register the TokenSecurityRealm
	* @param container - the BeanContainer for creating CDI beans
	* @param reflectiveClasses - producer to register classes for reflection
	* @return auth config item for the MP-JWT auth method and realm
	* @throws Exception
	*/
	@BuildStep
	@Record(ExecutionTime.STATIC_INIT)
	@SuppressWarnings({ "unchecked", "rawtypes" })
	AuthConfigBuildItem configureOIDCRealmAuthConfig(OIDCRecorder recorder, BuildProducer<ObjectSubstitutionBuildItem> objectSubstitution, BuildProducer<SecurityRealmBuildItem> securityRealm, BeanContainerBuildItem container, BuildProducer<ReflectiveClassBuildItem> reflectiveClasses) throws Exception {
		if (config.enabled) {
			// RSAPublicKey needs to be serialized
			//ObjectSubstitutionBuildItem.Holder pkHolder = new ObjectSubstitutionBuildItem.Holder(RSAPublicKey.class, PublicKeyProxy.class, PublicKeySubstitution.class);
			//ObjectSubstitutionBuildItem pkSub = new ObjectSubstitutionBuildItem(pkHolder);
			//objectSubstitution.produce(pkSub);

			RuntimeValue<SecurityRealm> realm = recorder.createTokenRealm(container.getValue());
			AuthConfig authConfig = new AuthConfig();
			authConfig.setAuthMechanism(config.authMechanism);
			authConfig.setRealmName(config.realmName);
			securityRealm.produce(new SecurityRealmBuildItem(realm, authConfig));

			reflectiveClasses.produce(new ReflectiveClassBuildItem(false, false, JsonProviderImpl.class.getName()));
			reflectiveClasses.produce(new ReflectiveClassBuildItem(false, false, ClaimAttributes.class.getName()));
			reflectiveClasses.produce(new ReflectiveClassBuildItem(false, false, ElytronJwtCallerPrincipal.class.getName()));

			return new AuthConfigBuildItem(authConfig);
		}
		return null;
	}

	/**
	 * Create the JwtIdentityManager
	 *
	 * @param recorder - jwt runtime recorder
	 * @param securityDomain - the previously created TokenSecurityRealm
	 * @param identityManagerProducer - producer for the identity manager
	 */
	@BuildStep
	@Record(ExecutionTime.STATIC_INIT)
	void configureIdentityManager(OIDCRecorder recorder, SecurityDomainBuildItem securityDomain, BuildProducer<IdentityManagerBuildItem> identityManagerProducer) {
		if (config.enabled) {
			IdentityManager identityManager = recorder.createIdentityManager(securityDomain.getSecurityDomain());
			identityManagerProducer.produce(new IdentityManagerBuildItem(identityManager));
		}
	}

	/**
	 * Register the MP-JWT authentication servlet extension
	 *
	 * @param recorder - jwt runtime recorder
	 * @param container - the BeanContainer for creating CDI beans
	 * @return servlet extension build item
	 */
	@BuildStep
	@Record(ExecutionTime.STATIC_INIT)
	ServletExtensionBuildItem registerOIDCAuthExtension(OIDCRecorder recorder, BeanContainerBuildItem container) throws Exception {
		log.debugf("registerOIDCAuthExtension");
		if (config.enabled) {
			//configure AuthContextInfo bean in same step as AuthExtension so that it is available for injection. Quarkus beans are scoped by step and proxy would be needed if bean was added in another step.
			recorder.staticInitAuthContextInfo(container.getValue(), config);
			ServletExtension authExt = recorder.createAuthExtension(config.authMechanism, container.getValue());
			ServletExtensionBuildItem sebi = new ServletExtensionBuildItem(authExt);
			return sebi;
		}
		return null;
	}

	//native https is enabled so all providers are included in native image so this is redundant
	@BuildStep
	@Record(ExecutionTime.STATIC_INIT)
	void registerRSASigProvider(BuildProducer<JCAProviderBuildItem> jcaProviderProducer) {
		jcaProviderProducer.produce(new JCAProviderBuildItem(config.rsaSigProvider));
		//having JCE provider available causes undertow native image build error, exclude for now and don't encrypt state.
		//jcaProviderProducer.produce(new JCAProviderBuildItem(config.aesCryptProvider));

	}

	@BuildStep
	@Record(ExecutionTime.RUNTIME_INIT)
	void initOIDCAuthExtension(OIDCRecorder recorder, BeanContainerBuildItem container) throws Exception {
		log.debugf("initOIDCAuthExtension");
		if (config.enabled) {
			recorder.runtimeInitAuthContextInfo(container.getValue(), config);
		}

	}

}
