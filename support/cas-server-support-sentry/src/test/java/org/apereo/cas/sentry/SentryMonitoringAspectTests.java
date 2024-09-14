package org.apereo.cas.sentry;

import org.apereo.cas.config.CasSentryAutoConfiguration;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.monitor.Monitorable;
import org.apereo.cas.monitor.NotMonitorable;
import org.apereo.cas.test.CasTestExtension;
import org.apereo.cas.util.spring.boot.SpringBootTestAutoConfigurations;
import lombok.NoArgsConstructor;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import io.sentry.spring.boot.jakarta.SentryAutoConfiguration;
import static org.junit.jupiter.api.Assertions.*;

/**
 * This is {@link SentryMonitoringAspectTests}.
 *
 * @author Misagh Moayyed
 * @since 7.0.0
 */
@SpringBootTestAutoConfigurations
@SpringBootTest(classes = {
    SentryAutoConfiguration.class,
    CasSentryAutoConfiguration.class,
    SentryMonitoringAspectTests.SentryMonitoringTestConfiguration.class
})
@EnableConfigurationProperties(CasConfigurationProperties.class)
@EnableAspectJAutoProxy
@Tag("Simple")
@ExtendWith(CasTestExtension.class)
@AutoConfigureObservability
class SentryMonitoringAspectTests {

    @Autowired
    @Qualifier("greeter")
    private Greeter greeter;
    
    @Autowired
    @Qualifier("reporter")
    private Reporter reporter;
    
    @Autowired
    @Qualifier("realReporter")
    private Reporter realReporter;

    @Test
    void verifyOperation() throws Throwable {
        assertThrows(IllegalArgumentException.class, () -> greeter.greet(true));
        assertEquals("Hello", greeter.greet(false));
        assertEquals("Reporter", reporter.report());
        assertEquals("RealReporter", realReporter.report());
    }

    @TestConfiguration(value = "SentryMonitoringTestConfiguration", proxyBeanMethods = false)
    static class SentryMonitoringTestConfiguration {
        @Bean
        public Greeter greeter() {
            return fail -> {
                if (fail) {
                    throw new IllegalArgumentException("Failed");
                }
                return "Hello";
            };
        }

        @Bean
        public Reporter reporter() {
            return new Reporter() {
                @Override
                public Object report() {
                    return "Reporter";
                }
            };
        }

        @Bean
        public Reporter realReporter() {
            return new RealReporter();
        }
    }

    @FunctionalInterface
    @Monitorable(type = "Greeting")
    private interface Greeter {
        Object greet(boolean fail);
    }

    @FunctionalInterface
    @NotMonitorable
    private interface Reporter {
        Object report();
    }
    
    @NoArgsConstructor
    @NotMonitorable
    static class RealReporter implements Reporter {
        @Override
        public Object report() {
            return "RealReporter";
        }
    }
}
