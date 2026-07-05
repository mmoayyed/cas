package org.apereo.cas.metadata.rest;

import module java.base;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.metadata.CasConfigurationMetadataRepository;
import org.apereo.cas.test.CasTestExtension;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.cloud.autoconfigure.RefreshAutoConfiguration;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * This is {@link CasConfigurationMetadataServerEndpointTests}.
 *
 * @author Misagh Moayyed
 * @since 6.2.0
 */
@SpringBootTest(classes = {
    CasConfigurationMetadataServerEndpointTests.CasConfigurationMetadataTestConfiguration.class,
    RefreshAutoConfiguration.class
}, properties = {
    "management.endpoint.configurationMetadata.access=UNRESTRICTED",
    "management.endpoints.web.exposure.include=*"
}, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@ExtendWith(CasTestExtension.class)
@EnableConfigurationProperties(CasConfigurationProperties.class)
@Tag("CasConfiguration")
class CasConfigurationMetadataServerEndpointTests {
    @Autowired
    @Qualifier("mockMvc")
    private MockMvc mockMvc;

    @TestConfiguration(value = "CasConfigurationMetadataTestConfiguration", proxyBeanMethods = false)
    static class CasConfigurationMetadataTestConfiguration {
        @Bean
        public CasConfigurationMetadataServerEndpoint configurationMetadataEndpoint(final CasConfigurationProperties casProperties,
                                                                                   final ConfigurableApplicationContext applicationContext) {
            return new CasConfigurationMetadataServerEndpoint(casProperties, applicationContext, new CasConfigurationMetadataRepository());
        }
    }

    @Test
    void verifyOperation() throws Throwable {
        mockMvc.perform(get("/actuator/configurationMetadata")
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$").isNotEmpty());

        mockMvc.perform(get("/actuator/configurationMetadata/server.port")
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$").isNotEmpty());
    }
}
