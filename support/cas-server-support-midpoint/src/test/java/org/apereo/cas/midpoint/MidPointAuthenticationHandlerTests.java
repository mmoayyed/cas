package org.apereo.cas.midpoint;

import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.authentication.CoreAuthenticationTestUtils;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.config.CasCoreAuditAutoConfiguration;
import org.apereo.cas.config.CasCoreAuthenticationAutoConfiguration;
import org.apereo.cas.config.CasCoreAutoConfiguration;
import org.apereo.cas.config.CasCoreCookieAutoConfiguration;
import org.apereo.cas.config.CasCoreLogoutAutoConfiguration;
import org.apereo.cas.config.CasCoreMultifactorAuthenticationAutoConfiguration;
import org.apereo.cas.config.CasCoreMultifactorAuthenticationWebflowAutoConfiguration;
import org.apereo.cas.config.CasCoreNotificationsAutoConfiguration;
import org.apereo.cas.config.CasCoreServicesAutoConfiguration;
import org.apereo.cas.config.CasCoreTicketsAutoConfiguration;
import org.apereo.cas.config.CasCoreUtilAutoConfiguration;
import org.apereo.cas.config.CasCoreWebAutoConfiguration;
import org.apereo.cas.config.CasCoreWebflowAutoConfiguration;
import org.apereo.cas.config.CasPersonDirectoryAutoConfiguration;
import org.apereo.cas.config.MidPointAuthenticationConfiguration;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.test.CasTestExtension;
import org.apereo.cas.util.junit.EnabledIfListeningOnPort;
import org.apereo.cas.util.spring.beans.BeanContainer;
import org.apereo.cas.util.spring.boot.SpringBootTestAutoConfigurations;
import lombok.val;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
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
@Tag("MidPoint")
@SpringBootTest(classes = {
    MidPointAuthenticationConfiguration.class,
    CasCoreTicketsAutoConfiguration.class,
    CasCoreAuthenticationAutoConfiguration.class,
    CasCoreServicesAutoConfiguration.class,
    CasCoreLogoutAutoConfiguration.class,
    CasCoreAutoConfiguration.class,
    CasCoreWebAutoConfiguration.class,
    CasCoreAuditAutoConfiguration.class,
    CasPersonDirectoryAutoConfiguration.class,
    CasCoreCookieAutoConfiguration.class,
    CasCoreMultifactorAuthenticationAutoConfiguration.class,
    CasCoreMultifactorAuthenticationWebflowAutoConfiguration.class,
    CasCoreWebflowAutoConfiguration.class,
    CasCoreUtilAutoConfiguration.class,
    CasCoreNotificationsAutoConfiguration.class
},
    properties = {
        "cas.authn.midpoint.url=http://localhost:18181/midpoint/ws/rest",
        "cas.authn.midpoint.username=administrator",
        "cas.authn.midpoint.password=5ecr3t"
    })
@EnableConfigurationProperties(CasConfigurationProperties.class)
@EnabledIfListeningOnPort(port = 18181)
@SpringBootTestAutoConfigurations
@ExtendWith(CasTestExtension.class)
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
