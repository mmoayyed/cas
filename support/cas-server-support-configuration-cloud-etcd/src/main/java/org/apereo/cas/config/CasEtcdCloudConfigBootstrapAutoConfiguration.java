package org.apereo.cas.config;

import module java.base;
import org.apereo.cas.configuration.features.CasFeatureModule;
import org.apereo.cas.util.spring.boot.ConditionalOnFeatureEnabled;
import io.etcd.jetcd.Client;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.cloud.bootstrap.config.PropertySourceLocator;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.util.StringUtils;

/**
 * This is {@link CasEtcdCloudConfigBootstrapAutoConfiguration}.
 *
 * @author Misagh Moayyed
 * @since 8.0.0
 */
@Slf4j
@ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.CasConfiguration, module = "etcd")
@AutoConfiguration
public class CasEtcdCloudConfigBootstrapAutoConfiguration {
    /**
     * The CAS etc configuration key prefix.
     */
    public static final String CAS_CONFIGURATION_PREFIX = "cas.spring.cloud.etcd";

    /**
     * The name of the bean that creates etcd clients.
     */
    public static final String BEAN_NAME_CLIENT_FACTORY = "etcdClientFactory";

    /**
     * Creates a new etcd client every time it is asked for one; whoever asks closes the client once done.
     * A deployment that needs a client with credentials or TLS overrides this bean. The bean is a factory rather
     * than a client because Spring Cloud closes the bootstrap context that located the property sources once a refresh
     * is done, along with every closeable bean in it, while the property source it located is still in use.
     * Each client receives an executor of its own, so closing one client never affects another.
     *
     * @param environment the environment
     * @return the client factory
     */
    @Bean
    @ConditionalOnMissingBean(name = BEAN_NAME_CLIENT_FACTORY)
    public Supplier<Client> etcdClientFactory(final ConfigurableEnvironment environment) {
        val endpoints = StringUtils.commaDelimitedListToSet(environment.getRequiredProperty(CAS_CONFIGURATION_PREFIX + ".endpoints"));
        return () -> Client.builder()
            .endpoints(endpoints.toArray(String[]::new))
            .executorService(Executors.newVirtualThreadPerTaskExecutor())
            .build();
    }

    @Bean
    @ConditionalOnMissingBean(name = "etcdPropertySourceLocator")
    public PropertySourceLocator etcdPropertySourceLocator(
        @Qualifier(BEAN_NAME_CLIENT_FACTORY)
        final Supplier<Client> etcdClientFactory) {
        return new EtcdPropertySourceLocator(etcdClientFactory);
    }
}
