package org.apereo.cas.config;

import module java.base;
import io.etcd.jetcd.Client;
import lombok.val;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.cloud.bootstrap.config.PropertySourceLocator;
import org.springframework.context.annotation.Bean;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * This is {@link CasEtcdClientFactoryTests}.
 *
 * @author Misagh Moayyed
 * @since 8.0.0
 */
@Tag("CasConfiguration")
class CasEtcdClientFactoryTests {
    private static final List<Client> CUSTOM_CLIENTS = new CopyOnWriteArrayList<>();

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(CasEtcdCloudConfigBootstrapAutoConfiguration.class))
        .withPropertyValues(CasEtcdCloudConfigBootstrapAutoConfiguration.CAS_CONFIGURATION_PREFIX + ".endpoints=http://localhost:2379");

    @Test
    @SuppressWarnings("unchecked")
    void verifyDefaultFactoryCreatesNewClients() {
        contextRunner.run(context -> {
            assertNull(context.getStartupFailure());
            assertTrue(context.containsBean("etcdPropertySourceLocator"));
            val factory = (Supplier<Client>) context.getBean(CasEtcdCloudConfigBootstrapAutoConfiguration.BEAN_NAME_CLIENT_FACTORY, Supplier.class);
            try (Client first = factory.get(); Client second = factory.get()) {
                assertNotNull(first);
                assertNotSame(first, second);
            }
        });
    }

    @Test
    void verifyCustomFactoryIsUsed() {
        CUSTOM_CLIENTS.clear();
        contextRunner
            .withUserConfiguration(CustomEtcdClientFactoryConfiguration.class)
            .run(context -> {
                assertNull(context.getStartupFailure());
                val locator = context.getBean("etcdPropertySourceLocator", PropertySourceLocator.class);
                val source = locator.locate(context.getEnvironment());
                assertEquals("https://sso.example.org", source.getProperty("cas.server.name"));
                assertEquals(1, CUSTOM_CLIENTS.size());
                verify(CUSTOM_CLIENTS.getFirst()).close();
            });
    }

    @TestConfiguration(value = "CustomEtcdClientFactoryConfiguration", proxyBeanMethods = false)
    static class CustomEtcdClientFactoryConfiguration {
        @Bean
        public Supplier<Client> etcdClientFactory() {
            return () -> EtcdPropertySourceTests.newClient(CUSTOM_CLIENTS,
                Map.of("/cas/config/default/cas.server.name", "https://sso.example.org"));
        }
    }
}
