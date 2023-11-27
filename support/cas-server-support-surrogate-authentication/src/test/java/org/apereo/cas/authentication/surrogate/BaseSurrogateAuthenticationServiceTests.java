package org.apereo.cas.authentication.surrogate;

import org.apereo.cas.authentication.CoreAuthenticationTestUtils;
import org.apereo.cas.config.CasCookieConfiguration;
import org.apereo.cas.config.CasCoreAuthenticationConfiguration;
import org.apereo.cas.config.CasCoreAuthenticationHandlersConfiguration;
import org.apereo.cas.config.CasCoreAuthenticationMetadataConfiguration;
import org.apereo.cas.config.CasCoreAuthenticationPolicyConfiguration;
import org.apereo.cas.config.CasCoreAuthenticationPrincipalConfiguration;
import org.apereo.cas.config.CasCoreAuthenticationServiceSelectionStrategyConfiguration;
import org.apereo.cas.config.CasCoreAuthenticationSupportConfiguration;
import org.apereo.cas.config.CasCoreConfiguration;
import org.apereo.cas.config.CasCoreHttpConfiguration;
import org.apereo.cas.config.CasCoreLogoutConfiguration;
import org.apereo.cas.config.CasCoreMultifactorAuthenticationConfiguration;
import org.apereo.cas.config.CasCoreNotificationsConfiguration;
import org.apereo.cas.config.CasCoreRestConfiguration;
import org.apereo.cas.config.CasCoreServicesAuthenticationConfiguration;
import org.apereo.cas.config.CasCoreServicesConfiguration;
import org.apereo.cas.config.CasCoreTicketCatalogConfiguration;
import org.apereo.cas.config.CasCoreTicketIdGeneratorsConfiguration;
import org.apereo.cas.config.CasCoreTicketsConfiguration;
import org.apereo.cas.config.CasCoreTicketsSerializationConfiguration;
import org.apereo.cas.config.CasCoreUtilConfiguration;
import org.apereo.cas.config.CasCoreUtilSerializationConfiguration;
import org.apereo.cas.config.CasCoreWebConfiguration;
import org.apereo.cas.config.CasCoreWebflowConfiguration;
import org.apereo.cas.config.CasMultifactorAuthenticationWebflowConfiguration;
import org.apereo.cas.config.CasPersonDirectoryTestConfiguration;
import org.apereo.cas.config.CasThemesConfiguration;
import org.apereo.cas.config.CasWebApplicationServiceFactoryConfiguration;
import org.apereo.cas.config.CasWebflowContextConfiguration;
import org.apereo.cas.config.SurrogateAuthenticationAuditConfiguration;
import org.apereo.cas.config.SurrogateAuthenticationConfiguration;
import org.apereo.cas.config.SurrogateAuthenticationMetadataConfiguration;
import org.apereo.cas.config.SurrogateAuthenticationRestConfiguration;
import org.apereo.cas.config.SurrogateComponentSerializationConfiguration;
import org.apereo.cas.services.ServicesManager;
import lombok.val;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.aop.AopAutoConfiguration;
import org.springframework.boot.autoconfigure.mail.MailSenderAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.cloud.autoconfigure.RefreshAutoConfiguration;
import org.springframework.context.annotation.Import;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.*;

/**
 * This is {@link BaseSurrogateAuthenticationServiceTests}.
 *
 * @author Timur Duehr
 * @since 6.0.0
 */
public abstract class BaseSurrogateAuthenticationServiceTests {
    public static final String BANDERSON = "banderson";

    public static final String ADMIN = "casadmin";

    @Mock
    protected ServicesManager servicesManager;

    public abstract SurrogateAuthenticationService getService();

    @Test
    void verifyUserAllowedToProxy() throws Throwable {
        assertFalse(getService().getImpersonationAccounts(getTestUser()).isEmpty());
    }

    @Test
    void verifyUserNotAllowedToProxy() throws Throwable {
        assertTrue(getService().getImpersonationAccounts("unknown-user").isEmpty());
    }

    @Test
    void verifyProxying() throws Throwable {
        val service = Optional.of(CoreAuthenticationTestUtils.getService());
        val surrogateService = getService();
        assertTrue(surrogateService.canImpersonate(BANDERSON, CoreAuthenticationTestUtils.getPrincipal(getTestUser()), service));
        assertTrue(surrogateService.canImpersonate(BANDERSON, CoreAuthenticationTestUtils.getPrincipal(BANDERSON), service));
        assertFalse(surrogateService.canImpersonate("XXXX", CoreAuthenticationTestUtils.getPrincipal(getTestUser()), service));
        assertFalse(surrogateService.canImpersonate(getTestUser(), CoreAuthenticationTestUtils.getPrincipal(BANDERSON), service));
    }

    @Test
    void verifyWildcard() throws Throwable {
        val service = Optional.of(CoreAuthenticationTestUtils.getService());
        val admin = CoreAuthenticationTestUtils.getPrincipal(getAdminUser());
        assertTrue(getService().canImpersonate(BANDERSON, admin, service));
        assertTrue(getService().isWildcardedAccount(BANDERSON, admin));
    }

    public String getAdminUser() {
        return ADMIN;
    }

    public String getTestUser() {
        return "casuser";
    }

    @ImportAutoConfiguration({
        RefreshAutoConfiguration.class,
        MailSenderAutoConfiguration.class,
        SecurityAutoConfiguration.class,
        WebMvcAutoConfiguration.class,
        AopAutoConfiguration.class
    })
    @SpringBootConfiguration
    @Import({
        SurrogateAuthenticationConfiguration.class,
        SurrogateComponentSerializationConfiguration.class,
        SurrogateAuthenticationAuditConfiguration.class,
        SurrogateAuthenticationMetadataConfiguration.class,
        SurrogateAuthenticationRestConfiguration.class,
        CasCoreRestConfiguration.class,
        CasCoreAuthenticationPrincipalConfiguration.class,
        CasCoreAuthenticationPolicyConfiguration.class,
        CasCoreAuthenticationMetadataConfiguration.class,
        CasCoreAuthenticationSupportConfiguration.class,
        CasCoreAuthenticationHandlersConfiguration.class,
        CasWebApplicationServiceFactoryConfiguration.class,
        CasCoreHttpConfiguration.class,
        CasCoreUtilConfiguration.class,
        CasPersonDirectoryTestConfiguration.class,
        CasCoreAuthenticationConfiguration.class,
        CasCoreWebConfiguration.class,
        CasCoreServicesAuthenticationConfiguration.class,
        CasCoreServicesConfiguration.class,
        CasCoreWebflowConfiguration.class,
        CasWebflowContextConfiguration.class,
        CasCoreUtilSerializationConfiguration.class,
        CasCoreMultifactorAuthenticationConfiguration.class,
        CasMultifactorAuthenticationWebflowConfiguration.class,
        CasCoreConfiguration.class,
        CasCoreLogoutConfiguration.class,
        CasCookieConfiguration.class,
        CasThemesConfiguration.class,
        CasCoreNotificationsConfiguration.class,
        CasCoreAuthenticationServiceSelectionStrategyConfiguration.class,
        CasCoreTicketCatalogConfiguration.class,
        CasCoreTicketsSerializationConfiguration.class,
        CasCoreTicketIdGeneratorsConfiguration.class,
        CasCoreTicketsConfiguration.class
    })
    public static class SharedTestConfiguration {
    }
}
