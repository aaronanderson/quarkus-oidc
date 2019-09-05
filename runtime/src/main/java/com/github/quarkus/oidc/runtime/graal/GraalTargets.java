package com.github.quarkus.oidc.runtime.graal;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import org.jboss.logging.Logger;

import com.oracle.svm.core.annotate.Alias;
import com.oracle.svm.core.annotate.InjectAccessors;
import com.oracle.svm.core.annotate.RecomputeFieldValue;
import com.oracle.svm.core.annotate.Substitute;
import com.oracle.svm.core.annotate.TargetClass;

public class GraalTargets {

    @TargetClass(className = "net.minidev.asm.DynamicClassLoader")
    public static final class Target_DynamicClassLoader {

        @Substitute
        Class<?> defineClass(String name, byte[] bytes) throws ClassFormatError {
            return null;
        }
    }

    @TargetClass(className = "com.nimbusds.oauth2.sdk.http.HTTPRequest")
    public static final class Target_HTTPRequest {

        @Alias
        @RecomputeFieldValue(kind = RecomputeFieldValue.Kind.Reset)
        private static SSLSocketFactory defaultSSLSocketFactory = null;

        @Substitute
        public static SSLSocketFactory getDefaultSSLSocketFactory() {
            if (defaultSSLSocketFactory == null) {
                synchronized (Target_HTTPRequest.class) {
                    if (defaultSSLSocketFactory == null) {
                        try {
                            defaultSSLSocketFactory = (SSLSocketFactory) SSLContext.getDefault().getSocketFactory();

                        } catch (NoSuchAlgorithmException e) {
                            Logger.getLogger(Target_HTTPRequest.class.getName()).error("Error initializing socket", e);
                        }
                    }
                }
            }
            return defaultSSLSocketFactory;
        }

    }

    @TargetClass(className = "com.nimbusds.oauth2.sdk.id.Identifier")
    public static final class Target_Identifier {

        //Why doesn't GRAAL substitute JDK SecureRandom references automatically?!?!? It does for it's own JDK classes 
        @Alias
        @InjectAccessors(StaticSecureRandomAccessor.class)
        protected static SecureRandom secureRandom;

    }

    static class StaticSecureRandomAccessor {
        private static volatile SecureRandom RANDOM;

        static SecureRandom get() {
            SecureRandom result = RANDOM;
            if (result == null) {
                synchronized (StaticSecureRandomAccessor.class) {
                    if (result == null) {
                        result = new SecureRandom();
                        RANDOM = result;
                    }
                }
            }
            return result;
        }
    }
}
