package org.apereo.cas.config;

import module java.base;
import org.apereo.cas.adaptors.x509.authentication.principal.X509CertificateCredential;
import org.apereo.cas.api.AuthenticationRiskEvaluator;
import org.apereo.cas.api.PasswordlessUserAccountStore;
import org.apereo.cas.audit.AuditTrailRecordResolutionPlan;
import org.apereo.cas.audit.AuditTrailRecordResolutionPlanConfigurer;
import org.apereo.cas.authentication.CoreAuthenticationTestUtils;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.adaptive.geo.GeoLocationResponse;
import org.apereo.cas.authentication.adaptive.geo.GeoLocationService;
import org.apereo.cas.authentication.principal.PrincipalResolver;
import org.apereo.cas.authentication.principal.ServiceFactory;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.authentication.principal.resolvers.EchoingPrincipalResolver;
import org.apereo.cas.authentication.surrogate.SurrogateAuthenticationService;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.consent.ConsentDecisionBuilder;
import org.apereo.cas.consent.ConsentRepository;
import org.apereo.cas.consent.InMemoryConsentRepository;
import org.apereo.cas.grouper.GrouperFacade;
import org.apereo.cas.heimdall.AuthorizationDecisionReason;
import org.apereo.cas.heimdall.AuthorizationResponse;
import org.apereo.cas.heimdall.authorizer.repository.AuthorizableResourceRepository;
import org.apereo.cas.heimdall.engine.AuthorizationEngine;
import org.apereo.cas.interrupt.InterruptInquiryExecutionPlan;
import org.apereo.cas.logout.slo.SingleLogoutRequestExecutor;
import org.apereo.cas.mcp.CasMcpEvaluationContextFactory;
import org.apereo.cas.mcp.CasMcpGroupMembershipSource;
import org.apereo.cas.mcp.audit.CasMcpAuditor;
import org.apereo.cas.mcp.audit.CasMcpOperationAuditActionResolver;
import org.apereo.cas.mcp.audit.CasMcpOperationAuditResourceResolver;
import org.apereo.cas.mcp.groups.GrouperGroupMembershipSource;
import org.apereo.cas.mcp.groups.ScimGroupMembershipSource;
import org.apereo.cas.mcp.groups.SyncopeGroupMembershipSource;
import org.apereo.cas.mcp.resources.CasSettingResources;
import org.apereo.cas.mcp.tools.CasAdministrationTools;
import org.apereo.cas.mcp.tools.CasAuthenticationRiskTools;
import org.apereo.cas.mcp.tools.CasConsentAdministrationTools;
import org.apereo.cas.mcp.tools.CasConsentTools;
import org.apereo.cas.mcp.tools.CasDelegatedAuthenticationTools;
import org.apereo.cas.mcp.tools.CasGeoLocationTools;
import org.apereo.cas.mcp.tools.CasGroupMembershipTools;
import org.apereo.cas.mcp.tools.CasHeimdallTools;
import org.apereo.cas.mcp.tools.CasInterruptTools;
import org.apereo.cas.mcp.tools.CasJwtTokenTools;
import org.apereo.cas.mcp.tools.CasNotificationAdministrationTools;
import org.apereo.cas.mcp.tools.CasOAuthAdministrationTools;
import org.apereo.cas.mcp.tools.CasOidcFederationTools;
import org.apereo.cas.mcp.tools.CasOidcTools;
import org.apereo.cas.mcp.tools.CasOneTimeTokenAdministrationTools;
import org.apereo.cas.mcp.tools.CasOneTimeTokenTools;
import org.apereo.cas.mcp.tools.CasPasswordManagementAdministrationTools;
import org.apereo.cas.mcp.tools.CasPasswordManagementTools;
import org.apereo.cas.mcp.tools.CasPasswordlessTools;
import org.apereo.cas.mcp.tools.CasSamlIdPAdministrationTools;
import org.apereo.cas.mcp.tools.CasSamlIdPMetadataTools;
import org.apereo.cas.mcp.tools.CasSurrogateTools;
import org.apereo.cas.mcp.tools.CasTrustedDeviceAdministrationTools;
import org.apereo.cas.mcp.tools.CasTrustedDeviceTools;
import org.apereo.cas.mcp.tools.CasVerifiableCredentialTools;
import org.apereo.cas.mcp.tools.CasWebAuthnAdministrationTools;
import org.apereo.cas.mcp.tools.CasWebAuthnTools;
import org.apereo.cas.metadata.CasConfigurationMetadataRepository;
import org.apereo.cas.notifications.CommunicationsManager;
import org.apereo.cas.notifications.mail.EmailCommunicationResult;
import org.apereo.cas.notifications.sms.SmsRequest;
import org.apereo.cas.oidc.federation.chain.OidcFederationTrustChainResolver;
import org.apereo.cas.oidc.issuer.OidcIssuerService;
import org.apereo.cas.oidc.vc.issuer.deferred.OidcVerifiableCredentialDeferredIssuanceService;
import org.apereo.cas.oidc.vc.issuer.status.OidcVerifiableCredentialStatusListService;
import org.apereo.cas.otp.repository.credentials.OneTimeTokenCredentialRepository;
import org.apereo.cas.pac4j.client.DelegatedIdentityProviders;
import org.apereo.cas.pm.PasswordHistoryService;
import org.apereo.cas.pm.PasswordManagementService;
import org.apereo.cas.pm.impl.history.PasswordHistoryEntity;
import org.apereo.cas.scim.v2.ScimService;
import org.apereo.cas.services.CasRegisteredService;
import org.apereo.cas.services.OidcRegisteredService;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.support.saml.services.SamlRegisteredService;
import org.apereo.cas.support.saml.services.idp.metadata.cache.CachedMetadataResolverResult;
import org.apereo.cas.support.saml.services.idp.metadata.cache.SamlRegisteredServiceCachingMetadataResolver;
import org.apereo.cas.syncope.SyncopeUtils;
import org.apereo.cas.ticket.accesstoken.OAuth20AccessToken;
import org.apereo.cas.ticket.registry.TicketRegistry;
import org.apereo.cas.token.JwtBuilder;
import org.apereo.cas.trusted.authentication.api.MultifactorAuthenticationTrustStorage;
import org.apereo.cas.version.EntityHistoryRepository;
import org.apereo.cas.web.support.ThrottledSubmissionsStore;
import org.apereo.cas.webauthn.storage.WebAuthnCredentialRepository;
import com.nimbusds.jwt.JWTClaimsSet;
import edu.internet2.middleware.grouperClient.ws.beans.WsGetGroupsResult;
import edu.internet2.middleware.grouperClient.ws.beans.WsGroup;
import lombok.val;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.boot.logging.LoggingSystem;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * This is {@link CasMcpAutoConfigurationTests}.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@Tag("MCP")
class CasMcpAutoConfigurationTests {
    private static ApplicationContextRunner consentContextRunner() {
        return new ApplicationContextRunner()
            .withUserConfiguration(CasMcpAutoConfiguration.CasMcpConsentConfiguration.class)
            .withBean(ConsentRepository.BEAN_NAME, ConsentRepository.class, InMemoryConsentRepository::new);
    }

    @Test
    void verifyConsentToolsWhenConsentIsAvailable() {
        consentContextRunner().run(context -> {
            assertNull(context.getStartupFailure());
            assertTrue(context.containsBean("casConsentTools"));
            val result = context.getBean(CasConsentTools.class).findConsentDecisions("casuser");
            assertEquals(0, result.count());
        });
    }

    @Test
    void verifyConsentToolsWithoutConsentModule() {
        consentContextRunner()
            .withClassLoader(new FilteredClassLoader(ConsentRepository.class, ConsentDecisionBuilder.class))
            .run(context -> {
                assertNull(context.getStartupFailure());
                assertFalse(context.containsBean("casConsentTools"));
            });
    }

    @Test
    void verifyConsentToolsCanBeDisabled() {
        consentContextRunner()
            .withPropertyValues("CasFeatureModule.AI.mcp-consent.enabled=false")
            .run(context -> {
                assertNull(context.getStartupFailure());
                assertFalse(context.containsBean("casConsentTools"));
            });
    }

    @Test
    void verifyConsentToolsWithoutConsentRepository() {
        new ApplicationContextRunner()
            .withUserConfiguration(CasMcpAutoConfiguration.CasMcpConsentConfiguration.class)
            .run(context -> {
                assertNull(context.getStartupFailure());
                val result = context.getBean(CasConsentTools.class).findConsentDecisions("casuser");
                assertEquals("Attribute consent is not configured", result.reason());
            });
    }

    @Test
    void verifySamlIdPToolsActivation() {
        val runner = new ApplicationContextRunner()
            .withUserConfiguration(CasMcpAutoConfiguration.CasMcpSamlIdPConfiguration.class)
            .withBean(ServicesManager.BEAN_NAME, ServicesManager.class, () -> mock(ServicesManager.class));
        runner.run(context -> assertTrue(context.containsBean("casSamlIdPMetadataTools")));
        runner.withClassLoader(new FilteredClassLoader(SamlRegisteredServiceCachingMetadataResolver.class))
            .run(context -> assertFalse(context.containsBean("casSamlIdPMetadataTools")));
        runner.withPropertyValues("CasFeatureModule.AI.mcp-saml-idp.enabled=false")
            .run(context -> assertFalse(context.containsBean("casSamlIdPMetadataTools")));
        runner.run(context -> {
            val result = context.getBean(CasSamlIdPMetadataTools.class).resolveSamlMetadata("https://sp.example.org");
            assertEquals("The SAML2 identity provider is not configured", result.reason());
        });
    }

    @Test
    void verifyOidcToolsActivation() {
        val runner = new ApplicationContextRunner()
            .withUserConfiguration(CasMcpAutoConfiguration.CasMcpOidcConfiguration.class)
            .withBean(ServicesManager.BEAN_NAME, ServicesManager.class, () -> mock(ServicesManager.class));
        runner.run(context -> assertTrue(context.containsBean("casOidcTools")));
        runner.withClassLoader(new FilteredClassLoader(OidcIssuerService.class))
            .run(context -> assertFalse(context.containsBean("casOidcTools")));
        runner.withClassLoader(new FilteredClassLoader(OidcRegisteredService.class))
            .run(context -> assertFalse(context.containsBean("casOidcTools")));
        runner.withPropertyValues("CasFeatureModule.AI.mcp-oidc.enabled=false")
            .run(context -> assertFalse(context.containsBean("casOidcTools")));
        runner.run(context -> {
            val result = context.getBean(CasOidcTools.class).listJwksKeys();
            assertEquals("The OpenID Connect keystore is not available", result.reason());
        });
    }

    @Test
    void verifyOAuthActivation() {
        val runner = new ApplicationContextRunner()
            .withUserConfiguration(CasMcpAutoConfiguration.CasMcpOAuthConfiguration.class)
            .withBean(OidcIssuerService.BEAN_NAME, OidcIssuerService.class, () -> OidcIssuerService.echoing("https://sso.example.org/cas/oidc"));
        runner.run(context -> {
            assertNull(context.getStartupFailure());
            assertTrue(context.containsBean("casMcpOAuthEndpointConfigurer"));
            assertTrue(context.containsBean("casMcpProtectedResourceMetadataController"));
        });
        runner.withClassLoader(new FilteredClassLoader(OAuth20AccessToken.class))
            .run(context -> assertFalse(context.containsBean("casMcpOAuthEndpointConfigurer")));
        runner.withClassLoader(new FilteredClassLoader(OidcIssuerService.class))
            .run(context -> assertFalse(context.containsBean("casMcpProtectedResourceMetadataController")));
        runner.withPropertyValues("CasFeatureModule.AI.mcp-oauth.enabled=false")
            .run(context -> assertFalse(context.containsBean("casMcpOAuthEndpointConfigurer")));
    }

    @Test
    void verifyTrustedDeviceToolsActivation() {
        val runner = new ApplicationContextRunner()
            .withUserConfiguration(CasMcpAutoConfiguration.CasMcpTrustedDevicesConfiguration.class);
        runner.run(context -> assertTrue(context.containsBean("casTrustedDeviceTools")));
        runner.withClassLoader(new FilteredClassLoader(MultifactorAuthenticationTrustStorage.class))
            .run(context -> assertFalse(context.containsBean("casTrustedDeviceTools")));
        runner.withPropertyValues("CasFeatureModule.AI.mcp-trusted-mfa.enabled=false")
            .run(context -> assertFalse(context.containsBean("casTrustedDeviceTools")));
        runner.run(context -> {
            val result = context.getBean(CasTrustedDeviceTools.class).findTrustedDevices("casuser");
            assertEquals("Multifactor authentication trusted devices are not configured", result.reason());
        });
    }

    @Test
    void verifySurrogateToolsActivation() {
        val runner = new ApplicationContextRunner()
            .withUserConfiguration(CasMcpAutoConfiguration.CasMcpSurrogateConfiguration.class)
            .withBean(WebApplicationService.BEAN_NAME_FACTORY, ServiceFactory.class, () -> mock(ServiceFactory.class));
        runner.run(context -> assertTrue(context.containsBean("casSurrogateTools")));
        runner.withClassLoader(new FilteredClassLoader(SurrogateAuthenticationService.class))
            .run(context -> assertFalse(context.containsBean("casSurrogateTools")));
        runner.withPropertyValues("CasFeatureModule.AI.mcp-surrogate.enabled=false")
            .run(context -> assertFalse(context.containsBean("casSurrogateTools")));
        runner.run(context -> {
            val result = context.getBean(CasSurrogateTools.class).findSurrogateAccounts("casuser", null);
            assertEquals("Surrogate authentication is not configured", result.reason());
        });
    }

    @Test
    void verifyInterruptToolsActivation() {
        val runner = new ApplicationContextRunner()
            .withUserConfiguration(CasMcpAutoConfiguration.CasMcpInterruptConfiguration.class)
            .withBean("casMcpEvaluationContextFactory", CasMcpEvaluationContextFactory.class, () -> mock(CasMcpEvaluationContextFactory.class));
        runner.run(context -> assertTrue(context.containsBean("casInterruptTools")));
        runner.withClassLoader(new FilteredClassLoader(InterruptInquiryExecutionPlan.class))
            .run(context -> assertFalse(context.containsBean("casInterruptTools")));
        runner.withPropertyValues("CasFeatureModule.AI.mcp-interrupt.enabled=false")
            .run(context -> assertFalse(context.containsBean("casInterruptTools")));
        runner.run(context -> {
            val result = context.getBean(CasInterruptTools.class).previewInterrupt("casuser", "https://mcp.example.org");
            assertEquals("Authentication interrupts are not configured", result.reason());
        });
    }

    @Test
    void verifyEvaluationContextWithoutAttributeRepositories() {
        val serviceFactory = mock(ServiceFactory.class);
        when(serviceFactory.createService(anyString())).thenReturn(mock(WebApplicationService.class));
        val factory = new CasMcpEvaluationContextFactory(mock(ServicesManager.class), serviceFactory, new EchoingPrincipalResolver());
        val context = factory.build("casuser", "https://mcp.example.org");
        assertEquals("casuser", context.principal().getId());
        assertEquals("casuser", context.authentication().getPrincipal().getId());
    }

    @Test
    void verifyAuthenticationRiskToolsActivation() {
        val runner = new ApplicationContextRunner()
            .withUserConfiguration(CasMcpAutoConfiguration.CasMcpAuthenticationRiskConfiguration.class)
            .withBean("casMcpEvaluationContextFactory", CasMcpEvaluationContextFactory.class, () -> mock(CasMcpEvaluationContextFactory.class));
        runner.run(context -> assertTrue(context.containsBean("casAuthenticationRiskTools")));
        runner.withClassLoader(new FilteredClassLoader(AuthenticationRiskEvaluator.class))
            .run(context -> assertFalse(context.containsBean("casAuthenticationRiskTools")));
        runner.withPropertyValues("CasFeatureModule.AI.mcp-electrofence.enabled=false")
            .run(context -> assertFalse(context.containsBean("casAuthenticationRiskTools")));
        runner.run(context -> {
            val result = context.getBean(CasAuthenticationRiskTools.class)
                .evaluateAuthenticationRisk("casuser", "https://mcp.example.org", "192.0.2.10", "Firefox", null);
            assertEquals("Risk-based authentication is not configured", result.reason());
        });
    }

    @Test
    void verifyOneTimeTokenToolsActivation() {
        val runner = new ApplicationContextRunner()
            .withUserConfiguration(CasMcpAutoConfiguration.CasMcpOneTimeTokenConfiguration.class);
        runner.run(context -> assertTrue(context.containsBean("casOneTimeTokenTools")));
        runner.withClassLoader(new FilteredClassLoader(OneTimeTokenCredentialRepository.class))
            .run(context -> assertFalse(context.containsBean("casOneTimeTokenTools")));
        runner.withPropertyValues("CasFeatureModule.AI.mcp-otp.enabled=false")
            .run(context -> assertFalse(context.containsBean("casOneTimeTokenTools")));
        runner.run(context -> {
            val result = context.getBean(CasOneTimeTokenTools.class).findOneTimeTokenAccounts("casuser");
            assertEquals("One-time password multifactor authentication is not configured", result.reason());
        });
    }

    @Test
    void verifyWebAuthnToolsActivation() {
        val runner = new ApplicationContextRunner()
            .withUserConfiguration(CasMcpAutoConfiguration.CasMcpWebAuthnConfiguration.class);
        runner.run(context -> assertTrue(context.containsBean("casWebAuthnTools")));
        runner.withClassLoader(new FilteredClassLoader(WebAuthnCredentialRepository.class))
            .run(context -> assertFalse(context.containsBean("casWebAuthnTools")));
        runner.withPropertyValues("CasFeatureModule.AI.mcp-webauthn.enabled=false")
            .run(context -> assertFalse(context.containsBean("casWebAuthnTools")));
        runner.run(context -> {
            val result = context.getBean(CasWebAuthnTools.class).findWebAuthnDevices("casuser");
            assertEquals("WebAuthn multifactor authentication is not configured", result.reason());
        });
    }

    @Test
    void verifyPasswordlessToolsActivation() {
        val runner = new ApplicationContextRunner()
            .withUserConfiguration(CasMcpAutoConfiguration.CasMcpPasswordlessConfiguration.class);
        runner.run(context -> assertTrue(context.containsBean("casPasswordlessTools")));
        runner.withClassLoader(new FilteredClassLoader(PasswordlessUserAccountStore.class))
            .run(context -> assertFalse(context.containsBean("casPasswordlessTools")));
        runner.withPropertyValues("CasFeatureModule.AI.mcp-passwordless.enabled=false")
            .run(context -> assertFalse(context.containsBean("casPasswordlessTools")));
        runner.run(context -> assertEquals("Passwordless authentication is not configured",
            context.getBean(CasPasswordlessTools.class).findPasswordlessAccount("casuser").reason()));
    }

    @Test
    void verifyDelegatedAuthenticationToolsActivation() {
        val runner = new ApplicationContextRunner()
            .withUserConfiguration(CasMcpAutoConfiguration.CasMcpDelegatedAuthenticationConfiguration.class)
            .withBean("casMcpEvaluationContextFactory", CasMcpEvaluationContextFactory.class, () -> mock(CasMcpEvaluationContextFactory.class));
        runner.run(context -> assertTrue(context.containsBean("casDelegatedAuthenticationTools")));
        runner.withClassLoader(new FilteredClassLoader(DelegatedIdentityProviders.class))
            .run(context -> assertFalse(context.containsBean("casDelegatedAuthenticationTools")));
        runner.withPropertyValues("CasFeatureModule.AI.mcp-delegated.enabled=false")
            .run(context -> assertFalse(context.containsBean("casDelegatedAuthenticationTools")));
        runner.run(context -> assertEquals("Delegated authentication is not configured",
            context.getBean(CasDelegatedAuthenticationTools.class).listIdentityProviders().reason()));
    }

    @Test
    void verifyHeimdallToolsActivation() {
        val runner = new ApplicationContextRunner()
            .withUserConfiguration(CasMcpAutoConfiguration.CasMcpHeimdallConfiguration.class)
            .withBean(PrincipalResolver.BEAN_NAME_PRINCIPAL_RESOLVER, PrincipalResolver.class, () -> mock(PrincipalResolver.class));
        runner.run(context -> assertTrue(context.containsBean("casHeimdallTools")));
        runner.withClassLoader(new FilteredClassLoader(AuthorizableResourceRepository.class))
            .run(context -> assertFalse(context.containsBean("casHeimdallTools")));
        runner.withPropertyValues("CasFeatureModule.AI.mcp-heimdall.enabled=false")
            .run(context -> assertFalse(context.containsBean("casHeimdallTools")));
        runner.run(context -> assertEquals("Heimdall is not configured",
            context.getBean(CasHeimdallTools.class).findAuthorizableResources("API").reason()));
    }

    @Test
    void verifySettingResourcesActivation() {
        val runner = new ApplicationContextRunner()
            .withUserConfiguration(CasMcpAutoConfiguration.CasMcpSettingsConfiguration.class);
        runner.run(context -> assertTrue(context.containsBean("casSettingResources") && context.containsBean("casSettingTools")));
        runner.withClassLoader(new FilteredClassLoader(CasConfigurationMetadataRepository.class))
            .run(context -> assertFalse(context.containsBean("casSettingResources")));
        runner.withPropertyValues("CasFeatureModule.AI.mcp-settings.enabled=false")
            .run(context -> assertFalse(context.containsBean("casSettingResources") || context.containsBean("casSettingTools")));
        runner.run(context -> assertTrue(context.getBean(CasSettingResources.class).describeSetting("cas.server.name")
            .contains("The CAS settings catalog is not available")));
    }

    @Test
    void verifyAuditConfigurationActivation() {
        val runner = new ApplicationContextRunner()
            .withUserConfiguration(CasMcpAutoConfiguration.CasMcpAuditConfiguration.class);
        runner.run(context -> {
            assertTrue(context.containsBean("casMcpAuditor"));
            assertTrue(context.containsBean("casMcpAuditAdvisor"));
            val plan = mock(AuditTrailRecordResolutionPlan.class);
            context.getBean("casMcpAuditTrailRecordResolutionPlanConfigurer", AuditTrailRecordResolutionPlanConfigurer.class)
                .configureAuditTrailRecordResolutionPlan(plan);
            verify(plan).registerAuditActionResolver(eq(CasMcpAuditor.AUDIT_ACTION_RESOLVER), any(CasMcpOperationAuditActionResolver.class));
            verify(plan).registerAuditResourceResolver(eq(CasMcpAuditor.AUDIT_RESOURCE_RESOLVER), any(CasMcpOperationAuditResourceResolver.class));
        });
        runner.withPropertyValues("CasFeatureModule.AI.mcp-audit.enabled=false")
            .run(context -> {
                assertFalse(context.containsBean("casMcpAuditor"));
                assertFalse(context.containsBean("casMcpAuditAdvisor"));
            });
    }

    @Test
    void verifyWriteToolsActivation() {
        val writeTools = List.of("casConsentAdministrationTools", "casTrustedDeviceAdministrationTools",
            "casOneTimeTokenAdministrationTools", "casWebAuthnAdministrationTools", "casOAuthAdministrationTools");
        val runner = new ApplicationContextRunner()
            .withUserConfiguration(CasMcpAutoConfiguration.CasMcpConsentConfiguration.class,
                CasMcpAutoConfiguration.CasMcpTrustedDevicesConfiguration.class,
                CasMcpAutoConfiguration.CasMcpOneTimeTokenConfiguration.class,
                CasMcpAutoConfiguration.CasMcpWebAuthnConfiguration.class,
                CasMcpAutoConfiguration.CasMcpOAuthAdministrationConfiguration.class)
            .withBean(TicketRegistry.BEAN_NAME, TicketRegistry.class, () -> mock(TicketRegistry.class))
            .withBean(ServicesManager.BEAN_NAME, ServicesManager.class, () -> mock(ServicesManager.class));
        runner.run(context -> {
            assertNull(context.getStartupFailure());
            assertTrue(context.containsBean("casTrustedDeviceTools"));
            writeTools.forEach(bean -> assertFalse(context.containsBean(bean), bean));
        });
        val enabled = runner.withPropertyValues("CasFeatureModule.AI.mcp-write.enabled=true");
        enabled.run(context -> {
            assertNull(context.getStartupFailure());
            writeTools.forEach(bean -> assertTrue(context.containsBean(bean), bean));
            assertEquals("Attribute consent is not configured",
                context.getBean(CasConsentAdministrationTools.class).revokeConsentDecisions("casuser", null).reason());
            assertEquals("Multifactor authentication trusted devices are not configured",
                context.getBean(CasTrustedDeviceAdministrationTools.class).removeTrustedDevices("casuser", null).reason());
            assertEquals("One-time password multifactor authentication is not configured",
                context.getBean(CasOneTimeTokenAdministrationTools.class).removeOneTimeTokenAccounts("casuser", null).reason());
            assertEquals("WebAuthn multifactor authentication is not configured",
                context.getBean(CasWebAuthnAdministrationTools.class).removeWebAuthnDevices("casuser").reason());
            assertEquals("A username or a client id is required",
                context.getBean(CasOAuthAdministrationTools.class).revokeOAuthTokens(null, null).reason());
        });
        enabled.withClassLoader(new FilteredClassLoader(OAuth20AccessToken.class))
            .run(context -> assertFalse(context.containsBean("casOAuthAdministrationTools")));
    }

    @Test
    void verifyAdministrationToolsWithoutDependencies() {
        val beanFactory = new StaticListableBeanFactory();
        val tools = new CasAdministrationTools(mock(TicketRegistry.class), mock(ServicesManager.class), mock(CasMcpEvaluationContextFactory.class),
            beanFactory.getBeanProvider(SingleLogoutRequestExecutor.class), beanFactory.getBeanProvider(ThrottledSubmissionsStore.class),
            beanFactory.getBeanProvider(LoggingSystem.class));
        assertEquals("Single logout is not available", tools.revokeSessions("casuser", null).reason());
        assertEquals("No throttle store is available", tools.releaseThrottledLogins("casuser", null).reason());
        assertEquals("The logging system is not available", tools.setLogLevel("org.apereo.cas", "DEBUG").reason());
        assertEquals("No registered service has this id", tools.setServiceEnabled(1, false).reason());
    }
    @Test
    void verifyOptionalToolGroupsActivation() {
        val runner = new ApplicationContextRunner()
            .withUserConfiguration(
                CasMcpAutoConfiguration.CasMcpPasswordManagementConfiguration.class,
                CasMcpAutoConfiguration.CasMcpX509Configuration.class,
                CasMcpAutoConfiguration.CasMcpJwtTokenConfiguration.class,
                CasMcpAutoConfiguration.CasMcpOidcFederationConfiguration.class,
                CasMcpAutoConfiguration.CasMcpVerifiableCredentialConfiguration.class,
                CasMcpAutoConfiguration.CasMcpGroupMembershipConfiguration.class,
                CasMcpAutoConfiguration.CasMcpServiceHistoryConfiguration.class,
                CasMcpAutoConfiguration.CasMcpOAuthTokensConfiguration.class)
            .withBean(ServicesManager.BEAN_NAME, ServicesManager.class, () -> mock(ServicesManager.class))
            .withBean(TicketRegistry.BEAN_NAME, TicketRegistry.class, () -> mock(TicketRegistry.class))
            .withBean(WebApplicationService.BEAN_NAME_FACTORY, ServiceFactory.class, () -> mock(ServiceFactory.class));
        val groups = Map.of(
            "mcp-pm", "casPasswordManagementTools",
            "mcp-x509", "casX509Tools",
            "mcp-token", "casJwtTokenTools",
            "mcp-oidc-federation", "casOidcFederationTools",
            "mcp-oidc-vc", "casVerifiableCredentialTools",
            "mcp-groups", "casGroupMembershipTools",
            "mcp-history", "casServiceHistoryTools",
            "mcp-oauth-tokens", "casOAuthTools");
        runner.run(context -> {
            assertNull(context.getStartupFailure());
            groups.values().forEach(bean -> assertTrue(context.containsBean(bean), bean));
            assertEquals(3, context.getBeansOfType(CasMcpGroupMembershipSource.class).size());
            assertFalse(context.containsBean("casPasswordManagementAdministrationTools"));
        });
        groups.forEach((group, bean) -> runner.withPropertyValues("CasFeatureModule.AI.%s.enabled=false".formatted(group))
            .run(context -> assertFalse(context.containsBean(bean), bean)));
        runner.withPropertyValues("CasFeatureModule.AI.mcp-write.enabled=true")
            .run(context -> assertTrue(context.containsBean("casPasswordManagementAdministrationTools")));
        runner.withClassLoader(new FilteredClassLoader(PasswordManagementService.class, X509CertificateCredential.class,
                OidcFederationTrustChainResolver.class, OidcVerifiableCredentialStatusListService.class, EntityHistoryRepository.class,
                GrouperFacade.class, ScimService.class, SyncopeUtils.class))
            .run(context -> {
                assertNull(context.getStartupFailure());
                List.of("casPasswordManagementTools", "casX509Tools", "casOidcFederationTools", "casVerifiableCredentialTools",
                    "casServiceHistoryTools").forEach(bean -> assertFalse(context.containsBean(bean), bean));
                assertTrue(context.containsBean("casGroupMembershipTools"));
                assertTrue(context.getBeansOfType(CasMcpGroupMembershipSource.class).isEmpty());
            });
    }

    @Test
    void verifyPasswordManagementTools() throws Throwable {
        val service = mock(PasswordManagementService.class);
        when(service.findEmails(any())).thenReturn(Set.of("casuser@example.org"));
        when(service.findPhone(any())).thenReturn("+1 555 0100 42");
        when(service.getSecurityQuestions(any())).thenReturn(Map.of("Pet?", "Rex"));
        when(service.unlockAccount(any())).thenReturn(true);
        val history = mock(PasswordHistoryService.class);
        val entry = new PasswordHistoryEntity();
        entry.setUsername("casuser");
        entry.setPassword("hashed-password-value");
        doReturn(List.of(entry)).when(history).fetch("casuser");
        val beanFactory = new StaticListableBeanFactory();
        beanFactory.addBean(PasswordManagementService.DEFAULT_BEAN_NAME, service);
        beanFactory.addBean(PasswordHistoryService.BEAN_NAME, history);

        val status = new CasPasswordManagementTools(beanFactory.getBeanProvider(PasswordManagementService.class),
            beanFactory.getBeanProvider(PasswordHistoryService.class)).findAccountStatus("casuser");
        assertNull(status.reason());
        assertEquals(List.of("c***@example.org"), status.emails());
        assertEquals("***42", status.phone());
        assertEquals(1, status.securityQuestions());
        assertEquals(1, status.passwordHistory());
        assertNotNull(status.latestPasswordChange());
        assertFalse(status.toString().contains("hashed-password-value"));
        assertFalse(status.toString().contains("Rex"));

        val unlocked = new CasPasswordManagementAdministrationTools(beanFactory.getBeanProvider(PasswordManagementService.class))
            .unlockAccount("casuser");
        assertTrue(unlocked.unlocked());
        verify(service).unlockAccount(argThat(credential -> "casuser".equals(credential.getId())));
    }

    @Test
    void verifyGroupMembershipSources() {
        val group = new WsGroup();
        group.setName("apereo:staff");
        val result = new WsGetGroupsResult();
        result.setWsGroups(new WsGroup[]{group});
        val grouperFacade = mock(GrouperFacade.class);
        when(grouperFacade.getGroupsForSubjectId("casuser")).thenReturn(List.of(result));

        val scimService = mock(ScimService.class);
        when(scimService.findUser(any(), eq("casuser"))).thenThrow(new IllegalStateException("SCIM server is unreachable"));

        val beanFactory = new StaticListableBeanFactory();
        beanFactory.addBean("grouper", new GrouperGroupMembershipSource(providerOf(GrouperFacade.class, grouperFacade)));
        beanFactory.addBean("scim", new ScimGroupMembershipSource(providerOf(ScimService.class, scimService)));
        beanFactory.addBean("syncope", new SyncopeGroupMembershipSource(new CasConfigurationProperties()));
        beanFactory.addBean("failing", new CasMcpGroupMembershipSource() {
            @Override
            public String getName() {
                return "Failing";
            }

            @Override
            public Optional<List<String>> findGroups(final String username) {
                throw new IllegalStateException("Unreachable");
            }
        });
        val memberships = new CasGroupMembershipTools(beanFactory.getBeanProvider(CasMcpGroupMembershipSource.class))
            .findGroupMemberships("casuser");
        assertNull(memberships.reason());
        val bySource = memberships.sources().stream()
            .collect(Collectors.toMap(CasGroupMembershipTools.GroupSource::source, Function.identity()));
        assertEquals(List.of("apereo:staff"), bySource.get("Grouper").groups());
        assertEquals("SCIM server is unreachable", bySource.get("SCIM").error());
        assertEquals("Unreachable", bySource.get("Failing").error());
        assertFalse(bySource.containsKey("Apache Syncope"));
    }

    @Test
    void verifyOptionalToolsWithMockedServices() throws Throwable {
        val federationService = new OidcRegisteredService();
        federationService.setClientId("https://rp.example.org");
        federationService.setServiceId("^https://rp.example.org/callback");
        federationService.setScopes(Set.of("openid", "profile"));
        federationService.setJwks("{\"keys\":[]}");
        val trustChainResolver = mock(OidcFederationTrustChainResolver.class);
        when(trustChainResolver.resolveTrustChains("https://rp.example.org")).thenReturn(Optional.of(federationService));
        val federationTools = new CasOidcFederationTools(providerOf(OidcFederationTrustChainResolver.class, trustChainResolver),
            new CasConfigurationProperties());
        val trusted = federationTools.resolveOidcTrustChain("https://rp.example.org");
        assertTrue(trusted.trusted());
        assertTrue(Objects.requireNonNull(trusted.registration()).keysDefined());
        assertFalse(trusted.toString().contains("{\"keys\""));
        assertFalse(federationTools.resolveOidcTrustChain("https://other.example.org").trusted());
        assertNotNull(federationTools.resolveOidcTrustChain("http://rp.example.org").reason());

        val statusList = mock(OidcVerifiableCredentialStatusListService.class);
        when(statusList.getEntries("casuser")).thenReturn(List.of(new OidcVerifiableCredentialStatusListService.StatusEntry("list-1", 7,
            "https://cas.example.org/status/list-1", OidcVerifiableCredentialStatusListService.StatusType.SUSPENDED, "casuser", "wallet",
            "UniversityDegree", "credential-1", Instant.now().plusSeconds(3600).getEpochSecond())));
        val vcTools = new CasVerifiableCredentialTools(providerOf(OidcVerifiableCredentialStatusListService.class, statusList),
            new StaticListableBeanFactory().getBeanProvider(OidcVerifiableCredentialDeferredIssuanceService.class));
        val vc = vcTools.findVerifiableCredentialStatus("casuser");
        assertEquals("SUSPENDED", vc.credentials().getFirst().status());
        assertTrue(vc.deferredRequests().isEmpty());

        val engine = mock(AuthorizationEngine.class);
        when(engine.authorize(any())).thenReturn(AuthorizationResponse.unauthorized("Denied by policy")
            .setReason(AuthorizationDecisionReason.POLICY_DENIED));
        val heimdallTools = new CasHeimdallTools(new StaticListableBeanFactory().getBeanProvider(AuthorizableResourceRepository.class),
            providerOf(AuthorizationEngine.class, engine), new EchoingPrincipalResolver());
        val decision = heimdallTools.checkAuthorization("casuser", null, null, null, "document", "doc-1", "can_read");
        assertFalse(decision.authorized());
        assertEquals("POLICY_DENIED", decision.decisionReason());
        assertEquals("Denied by policy", decision.message());
        verify(engine).authorize(argThat(request -> request.isAuthZen() && "casuser".equals(request.getSubject().getId())
            && request.getPrincipal() != null));
        assertNotNull(heimdallTools.checkAuthorization("casuser", null, "GET", null, null, null, null).reason());
        val unresolved = new CasHeimdallTools(new StaticListableBeanFactory().getBeanProvider(AuthorizableResourceRepository.class),
            providerOf(AuthorizationEngine.class, engine), mock(PrincipalResolver.class));
        assertEquals("The person cannot be resolved", unresolved.checkAuthorization("unknown", null, null, null, "document", "doc-1", "can_read").reason());

        val geoLocationService = mock(GeoLocationService.class);
        when(geoLocationService.locate("192.0.2.10")).thenReturn(GeoLocationResponse.builder().latitude(40.71).longitude(-74.0).build()
            .addAddress("New York"));
        when(geoLocationService.locate(40.71, -74.0)).thenReturn(GeoLocationResponse.builder().latitude(40.71).longitude(-74.0).build());
        val geoTools = new CasGeoLocationTools(providerOf(GeoLocationService.class, geoLocationService));
        assertEquals(List.of("New York"), geoTools.geolocateAddress("192.0.2.10").places());
        assertEquals(40.71, geoTools.geolocateAddress(" 40.71, -74.0 ").latitude());
        assertNotNull(geoTools.geolocateAddress("198.51.100.1").reason());

        val claims = new JWTClaimsSet.Builder().subject("casuser").issuer("https://cas.example.org").audience("https://app.example.org")
            .issueTime(new Date()).expirationTime(Date.from(Instant.now().minusSeconds(60))).claim("mail", "casuser@example.org").build();
        val jwtBuilder = mock(JwtBuilder.class);
        when(jwtBuilder.unpack(any(Optional.class), eq("header.payload.signature"))).thenReturn(claims);
        val registeredService = new CasRegisteredService();
        registeredService.setId(10);
        registeredService.setServiceId("https://app.example.org.*");
        val servicesManager = mock(ServicesManager.class);
        when(servicesManager.findServiceBy(10L)).thenReturn(registeredService);
        val jwtTools = new CasJwtTokenTools(providerOf(JwtBuilder.class, jwtBuilder), servicesManager, mock(ServiceFactory.class));
        val decoded = jwtTools.decodeJwtTicket("header.payload.signature", "10", null);
        assertTrue(decoded.verified(), decoded::toString);
        assertEquals("casuser", decoded.subject());
        assertTrue(decoded.expired());
        assertEquals(List.of("https://app.example.org"), decoded.audience());
        assertFalse(decoded.toString().contains("header.payload.signature"));
        assertFalse(jwtTools.decodeJwtTicket("other", "10", null).verified());
    }

    @Test
    void verifyWriteToolsWithMockedServices() throws Throwable {
        val samlService = new SamlRegisteredService();
        samlService.setId(20);
        samlService.setName("SP");
        samlService.setServiceId("https://sp.example.org");
        samlService.setMetadataLocation("https://sp.example.org/metadata");
        val servicesManager = mock(ServicesManager.class);
        doReturn(List.of(samlService)).when(servicesManager).getAllServicesOfType(SamlRegisteredService.class);
        val cachedResult = mock(CachedMetadataResolverResult.class);
        when(cachedResult.isResolved()).thenReturn(true);
        when(cachedResult.getEntityDescriptor()).thenReturn(Optional.empty());
        val metadataResolver = mock(SamlRegisteredServiceCachingMetadataResolver.class);
        when(metadataResolver.resolve(any(), any())).thenReturn(cachedResult);
        val refreshed = new CasSamlIdPAdministrationTools(servicesManager, providerOf(SamlRegisteredServiceCachingMetadataResolver.class, metadataResolver))
            .refreshSamlMetadata("https://sp.example.org");
        assertTrue(refreshed.invalidated());
        assertTrue(refreshed.resolved());
        verify(metadataResolver).invalidate(eq(samlService), any());
        val failingResolver = mock(SamlRegisteredServiceCachingMetadataResolver.class);
        doThrow(new IllegalStateException("Cache is unavailable")).when(failingResolver).invalidate(any(), any());
        val failed = new CasSamlIdPAdministrationTools(servicesManager, providerOf(SamlRegisteredServiceCachingMetadataResolver.class, failingResolver))
            .refreshSamlMetadata("https://sp.example.org");
        assertFalse(failed.invalidated());
        assertTrue(failed.reason().contains("Cache is unavailable"));

        val manager = mock(CommunicationsManager.class);
        when(manager.isMailSenderDefined()).thenReturn(true);
        when(manager.isSmsSenderDefined()).thenReturn(true);
        when(manager.email(any())).thenReturn(EmailCommunicationResult.builder().success(true).to(List.of("casuser@example.org")).build());
        when(manager.sms(any(SmsRequest.class))).thenReturn(true);
        val principalResolver = mock(PrincipalResolver.class);
        when(principalResolver.resolve(any(Credential.class), any(Optional.class), any(Optional.class), any(Optional.class)))
            .thenReturn(CoreAuthenticationTestUtils.getPrincipal("casuser",
                Map.<String, List<Object>>of("mail", List.of("casuser@example.org"), "phoneNumber", List.of("+15550100"))));
        val notifications = new CasNotificationAdministrationTools(providerOf(CommunicationsManager.class, manager), principalResolver);
        val email = notifications.sendTestNotification("casuser", CasNotificationAdministrationTools.NotificationChannel.EMAIL,
            "cas@example.org", null);
        assertTrue(email.sent(), email::toString);
        assertEquals(List.of("c***@example.org"), email.recipients());
        verify(manager).email(argThat(request -> request.getRecipients().equals(List.of("casuser@example.org"))));
        val sms = notifications.sendTestNotification("casuser", CasNotificationAdministrationTools.NotificationChannel.SMS, "CAS", null);
        assertTrue(sms.sent(), sms::toString);
        assertEquals("phoneNumber", sms.attribute());
        assertNotNull(notifications.sendTestNotification("casuser", CasNotificationAdministrationTools.NotificationChannel.EMAIL,
            "cas@example.org", "alternateEmail").reason());
    }

    private static <T> ObjectProvider<T> providerOf(final Class<T> type, final T bean) {
        val beanFactory = new StaticListableBeanFactory();
        beanFactory.addBean(type.getSimpleName(), bean);
        return beanFactory.getBeanProvider(type);
    }
}
