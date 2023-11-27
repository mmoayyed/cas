package org.apereo.cas.midpoint;

import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.authentication.CoreAuthenticationTestUtils;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.util.junit.EnabledIfListeningOnPort;
import org.apereo.cas.util.spring.beans.BeanContainer;
import lombok.val;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * This is {@link MidPointAuthenticationHandlerTests}.
 *
 * @author Misagh Moayyed
 * @since 7.0.0
 */
@Tag("midPoint")
@SpringBootTest(classes = BaseMidPointTests.SharedTestConfiguration.class,
    properties = {
        "cas.authn.midpoint.url=http://localhost:18181/midpoint/ws/rest",
        "cas.authn.midpoint.username=administrator",
        "cas.authn.midpoint.password=5ecr3t"
    })
@EnableConfigurationProperties(CasConfigurationProperties.class)
@EnabledIfListeningOnPort(port = 18181)
public class MidPointAuthenticationHandlerTests {

    @Autowired
    @Qualifier("midpointAuthenticationHandlers")
    private BeanContainer<AuthenticationHandler> midpointAuthenticationHandlers;

    @Autowired
    private CasConfigurationProperties casProperties;

    @Test
    void verifyHandlerPasses() throws Throwable {
        assertNotNull(midpointAuthenticationHandlers);
        val midpointAuthenticationHandler = midpointAuthenticationHandlers.first();
        val credential = CoreAuthenticationTestUtils.getCredentialsWithDifferentUsernameAndPassword(
            casProperties.getAuthn().getMidpoint().getUsername(), casProperties.getAuthn().getMidpoint().getPassword());
        val result = midpointAuthenticationHandler.authenticate(credential, mock(Service.class));
        assertNotNull(result);
    }
}
