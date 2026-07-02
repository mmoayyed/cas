package org.apereo.cas.support.oauth.services;

import module java.base;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.util.serialization.JacksonObjectMapperFactory;
import lombok.val;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;
import static org.hamcrest.Matchers.*;

/**
 * This is {@link OAuthRegisteredServiceClientSecretTests}.
 *
 * @author Misagh Moayyed
 * @since 8.0.0
 */
@Tag("OAuth")
class OAuthRegisteredServiceClientSecretTests {
    private static final ObjectMapper MAPPER = JacksonObjectMapperFactory.builder()
        .defaultTypingEnabled(true).build().toObjectMapper();

    @Test
    void verifyOperation() {
        val registeredService = new OAuthRegisteredService();
        registeredService.setName(UUID.randomUUID().toString());
        registeredService.setServiceId("testId");
        registeredService.setClientId(UUID.randomUUID().toString());
        registeredService.setClientSecrets(CollectionUtils.wrapList(
            new OAuthRegisteredServiceClientSecret(UUID.randomUUID().toString(), 1234567890)));
        val serialized = MAPPER.writeValueAsString(registeredService);
        val deserialized = MAPPER.readValue(serialized, OAuthRegisteredService.class);
        MatcherAssert.assertThat(deserialized.getClientSecrets(), is(registeredService.getClientSecrets()));
    }

    @Test
    void verifyCompatibility() {
        val serialized = """
                {
                  "@class" : "org.apereo.cas.support.oauth.services.OAuthRegisteredService",
                  "clientId": "clientid",
                  "clientSecret": "clientSecret",
                  "serviceId" : "^(https|imaps)://<redirect-uri>.*",
                  "name" : "OAuthService",
                  "id" : 100
                }
            """;
        val deserialized = MAPPER.readValue(serialized, OAuthRegisteredService.class);
        IO.println(deserialized.getClientSecrets());
    }
}
