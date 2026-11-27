package org.apereo.cas.config;

import module java.base;
import org.apereo.cas.adaptors.x509.authentication.principal.X509CertificateCredential;
import org.apereo.cas.api.AuthenticationRiskEvaluator;
import org.apereo.cas.api.PasswordlessUserAccountStore;
import org.apereo.cas.audit.AuditTrailExecutionPlan;
import org.apereo.cas.audit.AuditTrailRecordResolutionPlanConfigurer;
import org.apereo.cas.audit.AuditableExecution;
import org.apereo.cas.authentication.AuthenticationEventExecutionPlan;
import org.apereo.cas.authentication.MultifactorAuthenticationTriggerSelectionStrategy;
import org.apereo.cas.authentication.adaptive.geo.GeoLocationService;
import org.apereo.cas.authentication.attribute.AttributeDefinitionStore;
import org.apereo.cas.authentication.principal.PrincipalResolver;
import org.apereo.cas.authentication.principal.ServiceFactory;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.authentication.surrogate.SurrogateAuthenticationService;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.configuration.features.CasFeatureModule;
import org.apereo.cas.consent.ConsentDecisionBuilder;
import org.apereo.cas.consent.ConsentRepository;
import org.apereo.cas.grouper.GrouperFacade;
import org.apereo.cas.heimdall.authorizer.repository.AuthorizableResourceRepository;
import org.apereo.cas.heimdall.engine.AuthorizationEngine;
import org.apereo.cas.interrupt.InterruptInquirer;
import org.apereo.cas.interrupt.InterruptInquiryExecutionPlan;
import org.apereo.cas.logout.slo.SingleLogoutRequestExecutor;
import org.apereo.cas.logout.slo.SingleLogoutServiceLogoutUrlBuilder;
import org.apereo.cas.mcp.CasMcpConfirmationInterceptor;
import org.apereo.cas.mcp.CasMcpErrorHttpMessageConverter;
import org.apereo.cas.mcp.CasMcpEvaluationContextFactory;
import org.apereo.cas.mcp.CasMcpEventStreamFilter;
import org.apereo.cas.mcp.CasMcpGroupMembershipSource;
import org.apereo.cas.mcp.CasMcpSaml1ResponseRenderer;
import org.apereo.cas.mcp.audit.CasMcpAuditInterceptor;
import org.apereo.cas.mcp.audit.CasMcpAuditor;
import org.apereo.cas.mcp.audit.CasMcpOperationAuditActionResolver;
import org.apereo.cas.mcp.audit.CasMcpOperationAuditResourceResolver;
import org.apereo.cas.mcp.groups.GrouperGroupMembershipSource;
import org.apereo.cas.mcp.groups.ScimGroupMembershipSource;
import org.apereo.cas.mcp.groups.SyncopeGroupMembershipSource;
import org.apereo.cas.mcp.oauth.CasMcpAuthenticationEntryPoint;
import org.apereo.cas.mcp.oauth.CasMcpBearerTokenAuthenticationFilter;
import org.apereo.cas.mcp.oauth.CasMcpProtectedResource;
import org.apereo.cas.mcp.oauth.CasMcpProtectedResourceMetadataController;
import org.apereo.cas.mcp.prompts.CasMcpPrompts;
import org.apereo.cas.mcp.resources.CasServiceResources;
import org.apereo.cas.mcp.resources.CasSettingResources;
import org.apereo.cas.mcp.tools.CasAdministrationTools;
import org.apereo.cas.mcp.tools.CasAttributeTools;
import org.apereo.cas.mcp.tools.CasAuditTools;
import org.apereo.cas.mcp.tools.CasAuthenticationEventTools;
import org.apereo.cas.mcp.tools.CasAuthenticationRiskTools;
import org.apereo.cas.mcp.tools.CasConsentAdministrationTools;
import org.apereo.cas.mcp.tools.CasConsentTools;
import org.apereo.cas.mcp.tools.CasDelegatedAuthenticationTools;
import org.apereo.cas.mcp.tools.CasDeploymentTools;
import org.apereo.cas.mcp.tools.CasGeoLocationTools;
import org.apereo.cas.mcp.tools.CasGroupMembershipTools;
import org.apereo.cas.mcp.tools.CasHeimdallTools;
import org.apereo.cas.mcp.tools.CasInterruptTools;
import org.apereo.cas.mcp.tools.CasJwtTokenTools;
import org.apereo.cas.mcp.tools.CasLoginExplanationTools;
import org.apereo.cas.mcp.tools.CasMultifactorAuthenticationTools;
import org.apereo.cas.mcp.tools.CasNotificationAdministrationTools;
import org.apereo.cas.mcp.tools.CasOAuthAdministrationTools;
import org.apereo.cas.mcp.tools.CasOAuthTools;
import org.apereo.cas.mcp.tools.CasOidcFederationTools;
import org.apereo.cas.mcp.tools.CasOidcTools;
import org.apereo.cas.mcp.tools.CasOneTimeTokenAdministrationTools;
import org.apereo.cas.mcp.tools.CasOneTimeTokenTools;
import org.apereo.cas.mcp.tools.CasPasswordManagementAdministrationTools;
import org.apereo.cas.mcp.tools.CasPasswordManagementTools;
import org.apereo.cas.mcp.tools.CasPasswordlessTools;
import org.apereo.cas.mcp.tools.CasPersonDirectoryTools;
import org.apereo.cas.mcp.tools.CasSamlIdPAdministrationTools;
import org.apereo.cas.mcp.tools.CasSamlIdPMetadataTools;
import org.apereo.cas.mcp.tools.CasServerStatisticsTools;
import org.apereo.cas.mcp.tools.CasServiceAccessTools;
import org.apereo.cas.mcp.tools.CasServiceAdministrationTools;
import org.apereo.cas.mcp.tools.CasServiceHistoryTools;
import org.apereo.cas.mcp.tools.CasServiceManagementTools;
import org.apereo.cas.mcp.tools.CasSettingTools;
import org.apereo.cas.mcp.tools.CasSingleLogoutTools;
import org.apereo.cas.mcp.tools.CasSurrogateTools;
import org.apereo.cas.mcp.tools.CasTenantTools;
import org.apereo.cas.mcp.tools.CasThrottleTools;
import org.apereo.cas.mcp.tools.CasTicketExpirationTools;
import org.apereo.cas.mcp.tools.CasTicketRegistryTools;
import org.apereo.cas.mcp.tools.CasTrustedDeviceAdministrationTools;
import org.apereo.cas.mcp.tools.CasTrustedDeviceTools;
import org.apereo.cas.mcp.tools.CasValidationTools;
import org.apereo.cas.mcp.tools.CasVerifiableCredentialTools;
import org.apereo.cas.mcp.tools.CasWebAuthnAdministrationTools;
import org.apereo.cas.mcp.tools.CasWebAuthnTools;
import org.apereo.cas.mcp.tools.CasWebflowTools;
import org.apereo.cas.mcp.tools.CasX509Tools;
import org.apereo.cas.metadata.CasConfigurationMetadataRepository;
import org.apereo.cas.multitenancy.TenantsManager;
import org.apereo.cas.notifications.CommunicationsManager;
import org.apereo.cas.oidc.federation.chain.OidcFederationTrustChainResolver;
import org.apereo.cas.oidc.issuer.OidcIssuerService;
import org.apereo.cas.oidc.jwks.generator.OidcJsonWebKeystoreGeneratorService;
import org.apereo.cas.oidc.vc.issuer.deferred.OidcVerifiableCredentialDeferredIssuanceService;
import org.apereo.cas.oidc.vc.issuer.status.OidcVerifiableCredentialStatusListService;
import org.apereo.cas.otp.repository.credentials.OneTimeTokenCredentialRepository;
import org.apereo.cas.pac4j.client.DelegatedIdentityProviders;
import org.apereo.cas.persondir.PersonDirectoryAttributeRepositoryPlan;
import org.apereo.cas.pm.PasswordHistoryService;
import org.apereo.cas.pm.PasswordManagementService;
import org.apereo.cas.scim.v2.ScimService;
import org.apereo.cas.services.OidcRegisteredService;
import org.apereo.cas.services.ServiceRegistry;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.support.events.CasEventRepository;
import org.apereo.cas.support.oauth.validator.OAuth20ProofOfPossessionValidator;
import org.apereo.cas.support.saml.OpenSamlConfigBean;
import org.apereo.cas.support.saml.SamlUtils;
import org.apereo.cas.support.saml.authentication.SamlResponseBuilder;
import org.apereo.cas.support.saml.services.idp.metadata.cache.SamlRegisteredServiceCachingMetadataResolver;
import org.apereo.cas.syncope.SyncopeUtils;
import org.apereo.cas.throttle.AuthenticationThrottlingExecutionPlan;
import org.apereo.cas.ticket.ExpirationPolicyBuilder;
import org.apereo.cas.ticket.accesstoken.OAuth20AccessToken;
import org.apereo.cas.ticket.registry.TicketRegistry;
import org.apereo.cas.token.JwtBuilder;
import org.apereo.cas.trusted.authentication.api.MultifactorAuthenticationTrustStorage;
import org.apereo.cas.util.feature.CasRuntimeModuleLoader;
import org.apereo.cas.util.spring.boot.ConditionalOnFeatureEnabled;
import org.apereo.cas.util.text.MessageSanitizer;
import org.apereo.cas.validation.AuthenticationAttributeReleasePolicy;
import org.apereo.cas.version.EntityHistoryRepository;
import org.apereo.cas.web.CasWebSecurityConfigurer;
import org.apereo.cas.web.support.ThrottledSubmissionsStore;
import org.apereo.cas.webauthn.storage.WebAuthnCredentialRepository;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import io.modelcontextprotocol.server.McpAsyncServer;
import io.modelcontextprotocol.server.McpSyncServer;
import lombok.val;
import org.apache.commons.lang3.Strings;
import org.springframework.ai.mcp.annotation.McpResource;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.server.common.autoconfigure.McpServerAutoConfiguration;
import org.springframework.ai.mcp.server.common.autoconfigure.annotations.McpServerSpecificationFactoryAutoConfiguration;
import org.springframework.ai.mcp.server.common.autoconfigure.properties.McpServerStreamableHttpProperties;
import org.springframework.aop.Advisor;
import org.springframework.aop.support.ComposablePointcut;
import org.springframework.aop.support.DefaultPointcutAdvisor;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.boot.LazyInitializationExcludeFilter;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.logging.LoggingSystem;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Role;
import org.springframework.core.Ordered;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.http.converter.HttpMessageConverters;
import org.springframework.security.authorization.method.AuthorizationInterceptorsOrder;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * This is {@link CasMcpAutoConfiguration}.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@EnableConfigurationProperties({CasConfigurationProperties.class, McpServerStreamableHttpProperties.class})
@ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp")
@AutoConfiguration(before = {
    McpServerAutoConfiguration.class,
    McpServerSpecificationFactoryAutoConfiguration.class
})
@Lazy(false)
public class CasMcpAutoConfiguration {
    @Bean
    @ConditionalOnMissingBean(name = "casMcpLazyInitializationExcludeFilter")
    public static LazyInitializationExcludeFilter casMcpLazyInitializationExcludeFilter() {
        return LazyInitializationExcludeFilter.forBeanTypes(McpSyncServer.class, McpAsyncServer.class);
    }

    @Bean
    @ConditionalOnMissingBean(name = "casServiceManagementTools")
    public CasServiceManagementTools casServiceManagementTools(
        final ConfigurableApplicationContext applicationContext,
        @Qualifier(ServicesManager.BEAN_NAME)
        final ServicesManager servicesManager,
        @Qualifier(WebApplicationService.BEAN_NAME_FACTORY)
        final ServiceFactory<WebApplicationService> webApplicationServiceFactory) {
        return new CasServiceManagementTools(servicesManager, webApplicationServiceFactory,
            new CasServiceManagementTools.RegisteredServiceParser(applicationContext));
    }

    @Bean
    @ConditionalOnMissingBean(name = "casMcpEvaluationContextFactory")
    public CasMcpEvaluationContextFactory casMcpEvaluationContextFactory(
        @Qualifier(ServicesManager.BEAN_NAME)
        final ServicesManager servicesManager,
        @Qualifier(WebApplicationService.BEAN_NAME_FACTORY)
        final ServiceFactory<WebApplicationService> webApplicationServiceFactory,
        @Qualifier(PrincipalResolver.BEAN_NAME_PRINCIPAL_RESOLVER)
        final PrincipalResolver principalResolver) {
        return new CasMcpEvaluationContextFactory(servicesManager, webApplicationServiceFactory, principalResolver);
    }

    @Bean
    @ConditionalOnMissingBean(name = "casServiceAccessTools")
    public CasServiceAccessTools casServiceAccessTools(
        final ConfigurableApplicationContext applicationContext,
        @Qualifier("casMcpEvaluationContextFactory")
        final CasMcpEvaluationContextFactory casMcpEvaluationContextFactory,
        @Qualifier(AuditableExecution.AUDITABLE_EXECUTION_REGISTERED_SERVICE_ACCESS)
        final AuditableExecution registeredServiceAccessStrategyEnforcer) {
        return new CasServiceAccessTools(casMcpEvaluationContextFactory, registeredServiceAccessStrategyEnforcer, applicationContext);
    }

    @Bean
    @ConditionalOnMissingBean(name = "casTicketRegistryTools")
    public CasTicketRegistryTools casTicketRegistryTools(
        @Qualifier(TicketRegistry.BEAN_NAME)
        final TicketRegistry ticketRegistry) {
        return new CasTicketRegistryTools(ticketRegistry);
    }

    @Bean
    @ConditionalOnMissingBean(name = "casPersonDirectoryTools")
    public CasPersonDirectoryTools casPersonDirectoryTools(
        @Qualifier(PrincipalResolver.BEAN_NAME_PRINCIPAL_RESOLVER)
        final PrincipalResolver principalResolver) {
        return new CasPersonDirectoryTools(principalResolver);
    }

    @Bean
    @ConditionalOnMissingBean(name = "casMultifactorAuthenticationTools")
    public CasMultifactorAuthenticationTools casMultifactorAuthenticationTools(
        final ConfigurableApplicationContext applicationContext,
        @Qualifier("casMcpEvaluationContextFactory")
        final CasMcpEvaluationContextFactory casMcpEvaluationContextFactory,
        @Qualifier(MultifactorAuthenticationTriggerSelectionStrategy.BEAN_NAME)
        final ObjectProvider<MultifactorAuthenticationTriggerSelectionStrategy> triggerSelectionStrategy) {
        return new CasMultifactorAuthenticationTools(casMcpEvaluationContextFactory, triggerSelectionStrategy, applicationContext);
    }

    @Bean
    @ConditionalOnMissingBean(name = "casSingleLogoutTools")
    public CasSingleLogoutTools casSingleLogoutTools(
        final CasConfigurationProperties casProperties,
        @Qualifier(TicketRegistry.BEAN_NAME)
        final TicketRegistry ticketRegistry,
        @Qualifier(ServicesManager.BEAN_NAME)
        final ServicesManager servicesManager,
        @Qualifier("singleLogoutServiceLogoutUrlBuilder")
        final SingleLogoutServiceLogoutUrlBuilder singleLogoutServiceLogoutUrlBuilder) {
        return new CasSingleLogoutTools(ticketRegistry, servicesManager, singleLogoutServiceLogoutUrlBuilder, casProperties);
    }

    @Bean
    @ConditionalOnMissingBean(name = "casServerStatisticsTools")
    public CasServerStatisticsTools casServerStatisticsTools(
        @Qualifier(TicketRegistry.BEAN_NAME)
        final TicketRegistry ticketRegistry,
        @Qualifier(ServicesManager.BEAN_NAME)
        final ServicesManager servicesManager) {
        return new CasServerStatisticsTools(ticketRegistry, servicesManager);
    }

    @Bean
    @ConditionalOnMissingBean(name = "casTenantTools")
    public CasTenantTools casTenantTools(
        @Qualifier(TenantsManager.BEAN_NAME)
        final ObjectProvider<TenantsManager> tenantsManager) {
        return new CasTenantTools(tenantsManager);
    }

    @Bean
    @ConditionalOnMissingBean(name = "casAuditTools")
    public CasAuditTools casAuditTools(
        @Qualifier(AuditTrailExecutionPlan.BEAN_NAME)
        final AuditTrailExecutionPlan auditTrailExecutionPlan) {
        return new CasAuditTools(auditTrailExecutionPlan);
    }

    @Bean
    @ConditionalOnMissingBean(name = "casAuthenticationEventTools")
    public CasAuthenticationEventTools casAuthenticationEventTools(
        @Qualifier(CasEventRepository.BEAN_NAME)
        final ObjectProvider<CasEventRepository> casEventRepository) {
        return new CasAuthenticationEventTools(casEventRepository);
    }

    @Bean
    @ConditionalOnMissingBean(name = "casDeploymentTools")
    public CasDeploymentTools casDeploymentTools(
        final CasConfigurationProperties casProperties,
        final ConfigurableApplicationContext applicationContext,
        @Qualifier(TicketRegistry.BEAN_NAME)
        final TicketRegistry ticketRegistry,
        @Qualifier(ServiceRegistry.BEAN_NAME)
        final ObjectProvider<ServiceRegistry> serviceRegistry,
        @Qualifier(AuthenticationEventExecutionPlan.DEFAULT_BEAN_NAME)
        final ObjectProvider<AuthenticationEventExecutionPlan> authenticationEventExecutionPlan,
        @Qualifier(PersonDirectoryAttributeRepositoryPlan.BEAN_NAME)
        final ObjectProvider<PersonDirectoryAttributeRepositoryPlan> attributeRepositoryPlan,
        @Qualifier("casRuntimeModuleLoader")
        final ObjectProvider<CasRuntimeModuleLoader> casRuntimeModuleLoader) {
        return new CasDeploymentTools(casProperties, applicationContext, ticketRegistry, serviceRegistry,
            authenticationEventExecutionPlan, attributeRepositoryPlan, casRuntimeModuleLoader);
    }

    @Bean
    @ConditionalOnMissingBean(name = "casThrottleTools")
    public CasThrottleTools casThrottleTools(
        final CasConfigurationProperties casProperties,
        @Qualifier(ThrottledSubmissionsStore.BEAN_NAME)
        final ObjectProvider<ThrottledSubmissionsStore> throttledSubmissionsStore,
        @Qualifier(AuthenticationThrottlingExecutionPlan.BEAN_NAME)
        final ObjectProvider<AuthenticationThrottlingExecutionPlan> authenticationThrottlingExecutionPlan) {
        return new CasThrottleTools(casProperties, throttledSubmissionsStore, authenticationThrottlingExecutionPlan);
    }

    @Bean
    @ConditionalOnMissingBean(name = "casAttributeTools")
    public CasAttributeTools casAttributeTools(
        @Qualifier(PersonDirectoryAttributeRepositoryPlan.BEAN_NAME)
        final ObjectProvider<PersonDirectoryAttributeRepositoryPlan> attributeRepositoryPlan,
        @Qualifier(AttributeDefinitionStore.BEAN_NAME)
        final ObjectProvider<AttributeDefinitionStore> attributeDefinitionStore) {
        return new CasAttributeTools(attributeRepositoryPlan, attributeDefinitionStore);
    }

    @Bean
    @ConditionalOnMissingBean(name = "casLoginExplanationTools")
    public CasLoginExplanationTools casLoginExplanationTools(
        final CasConfigurationProperties casProperties,
        @Qualifier("casServiceAccessTools")
        final ObjectProvider<CasServiceAccessTools> casServiceAccessTools,
        @Qualifier("casMultifactorAuthenticationTools")
        final ObjectProvider<CasMultifactorAuthenticationTools> casMultifactorAuthenticationTools,
        @Qualifier("casAuthenticationRiskTools")
        final ObjectProvider<CasAuthenticationRiskTools> casAuthenticationRiskTools,
        @Qualifier("casInterruptTools")
        final ObjectProvider<CasInterruptTools> casInterruptTools) {
        return new CasLoginExplanationTools(casProperties, casServiceAccessTools, casMultifactorAuthenticationTools,
            casAuthenticationRiskTools, casInterruptTools);
    }

    @Bean
    @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-write", enabledByDefault = false)
    @ConditionalOnMissingBean(name = CasAdministrationTools.BEAN_NAME)
    public CasAdministrationTools casAdministrationTools(
        @Qualifier(TicketRegistry.BEAN_NAME)
        final TicketRegistry ticketRegistry,
        @Qualifier(ServicesManager.BEAN_NAME)
        final ServicesManager servicesManager,
        @Qualifier("casMcpEvaluationContextFactory")
        final CasMcpEvaluationContextFactory casMcpEvaluationContextFactory,
        @Qualifier(SingleLogoutRequestExecutor.BEAN_NAME)
        final ObjectProvider<SingleLogoutRequestExecutor> singleLogoutRequestExecutor,
        @Qualifier(ThrottledSubmissionsStore.BEAN_NAME)
        final ObjectProvider<ThrottledSubmissionsStore> throttledSubmissionsStore,
        final ObjectProvider<LoggingSystem> loggingSystem) {
        return new CasAdministrationTools(ticketRegistry, servicesManager, casMcpEvaluationContextFactory,
            singleLogoutRequestExecutor, throttledSubmissionsStore, loggingSystem);
    }

    @Bean
    @ConditionalOnMissingBean(name = "casServiceResources")
    public CasServiceResources casServiceResources(
        @Qualifier(ServicesManager.BEAN_NAME)
        final ServicesManager servicesManager,
        @Qualifier("casServiceManagementTools")
        final ObjectProvider<CasServiceManagementTools> casServiceManagementTools) {
        return new CasServiceResources(servicesManager, casServiceManagementTools);
    }

    @Bean
    @ConditionalOnMissingBean(name = "casMcpWebMvcConfigurer")
    public WebMvcConfigurer casMcpWebMvcConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void configureMessageConverters(final HttpMessageConverters.ServerBuilder builder) {
                builder.addCustomConverter(new CasMcpErrorHttpMessageConverter());
            }
        };
    }

    @Bean
    @ConditionalOnMissingBean(name = "casMcpEndpointConfigurer")
    public CasWebSecurityConfigurer<HttpSecurity> casMcpEndpointConfigurer(
        final McpServerStreamableHttpProperties mcpServerStreamableHttpProperties) {
        val endpoint = mcpServerStreamableHttpProperties.getMcpEndpoint();
        return new CasWebSecurityConfigurer<>() {
            @Override
            @CanIgnoreReturnValue
            public CasWebSecurityConfigurer<HttpSecurity> configure(final HttpSecurity http) throws Exception {
                http.authorizeHttpRequests(customizer -> customizer
                        .requestMatchers(PathPatternRequestMatcher.withDefaults().matcher(endpoint)).authenticated())
                    .httpBasic(Customizer.withDefaults())
                    .addFilterAfter(new CasMcpEventStreamFilter(PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.GET, endpoint)),
                        AuthorizationFilter.class);
                return this;
            }
        };
    }

    @ConditionalOnClass(ConsentRepository.class)
    @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-consent")
    @Configuration(value = "CasMcpConsentConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class CasMcpConsentConfiguration {
        @Bean
        @ConditionalOnMissingBean(name = "casConsentTools")
        public CasConsentTools casConsentTools(
            @Qualifier(ConsentRepository.BEAN_NAME)
            final ObjectProvider<ConsentRepository> consentRepository,
            @Qualifier(ConsentDecisionBuilder.BEAN_NAME)
            final ObjectProvider<ConsentDecisionBuilder> consentDecisionBuilder) {
            return new CasConsentTools(consentRepository, consentDecisionBuilder);
        }

        @Bean
        @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-write", enabledByDefault = false)
        @ConditionalOnMissingBean(name = "casConsentAdministrationTools")
        public CasConsentAdministrationTools casConsentAdministrationTools(
            @Qualifier(ConsentRepository.BEAN_NAME)
            final ObjectProvider<ConsentRepository> consentRepository) {
            return new CasConsentAdministrationTools(consentRepository);
        }
    }

    @ConditionalOnClass(SamlRegisteredServiceCachingMetadataResolver.class)
    @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-saml-idp")
    @Configuration(value = "CasMcpSamlIdPConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class CasMcpSamlIdPConfiguration {
        @Bean
        @ConditionalOnMissingBean(name = "casSamlIdPMetadataTools")
        public CasSamlIdPMetadataTools casSamlIdPMetadataTools(
            @Qualifier(ServicesManager.BEAN_NAME)
            final ServicesManager servicesManager,
            @Qualifier(SamlRegisteredServiceCachingMetadataResolver.BEAN_NAME)
            final ObjectProvider<SamlRegisteredServiceCachingMetadataResolver> metadataResolver) {
            return new CasSamlIdPMetadataTools(servicesManager, metadataResolver);
        }

        @Bean
        @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-write", enabledByDefault = false)
        @ConditionalOnMissingBean(name = "casSamlIdPAdministrationTools")
        public CasSamlIdPAdministrationTools casSamlIdPAdministrationTools(
            @Qualifier(ServicesManager.BEAN_NAME)
            final ServicesManager servicesManager,
            @Qualifier(SamlRegisteredServiceCachingMetadataResolver.BEAN_NAME)
            final ObjectProvider<SamlRegisteredServiceCachingMetadataResolver> metadataResolver) {
            return new CasSamlIdPAdministrationTools(servicesManager, metadataResolver);
        }
    }

    @ConditionalOnClass({OidcIssuerService.class, OidcRegisteredService.class})
    @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-oidc")
    @Configuration(value = "CasMcpOidcConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class CasMcpOidcConfiguration {
        @Bean
        @ConditionalOnMissingBean(name = "casOidcTools")
        public CasOidcTools casOidcTools(
            final CasConfigurationProperties casProperties,
            @Qualifier(ServicesManager.BEAN_NAME)
            final ServicesManager servicesManager,
            @Qualifier(OidcIssuerService.BEAN_NAME)
            final ObjectProvider<OidcIssuerService> oidcIssuerService,
            @Qualifier("oidcJsonWebKeystoreGeneratorService")
            final ObjectProvider<OidcJsonWebKeystoreGeneratorService> oidcJsonWebKeystoreGeneratorService) {
            return new CasOidcTools(servicesManager, oidcIssuerService, oidcJsonWebKeystoreGeneratorService, casProperties);
        }
    }

    @ConditionalOnClass({OidcIssuerService.class, OAuth20AccessToken.class})
    @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-oauth")
    @Configuration(value = "CasMcpOAuthConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties({CasConfigurationProperties.class, McpServerStreamableHttpProperties.class})
    static class CasMcpOAuthConfiguration {
        @Bean
        @ConditionalOnMissingBean(name = "casMcpProtectedResourceMetadataController")
        public CasMcpProtectedResourceMetadataController casMcpProtectedResourceMetadataController(
            final CasConfigurationProperties casProperties,
            final Environment environment,
            final McpServerStreamableHttpProperties mcpServerStreamableHttpProperties,
            @Qualifier(OidcIssuerService.BEAN_NAME)
            final ObjectProvider<OidcIssuerService> oidcIssuerService,
            @Qualifier("oauthProofOfPossessionValidator")
            final ObjectProvider<OAuth20ProofOfPossessionValidator> oauthProofOfPossessionValidator) {
            val protectedResource = CasMcpProtectedResource.of(casProperties, mcpServerStreamableHttpProperties.getMcpEndpoint());
            val writable = environment.getProperty(CasFeatureModule.FeatureCatalog.AI.toProperty("mcp-write"), Boolean.class, Boolean.FALSE);
            return new CasMcpProtectedResourceMetadataController(protectedResource, oidcIssuerService,
                environment.getProperty("spring.ai.mcp.server.name", "Apereo CAS MCP Server"), writable,
                oauthProofOfPossessionValidator, casProperties.getAuthn().getOidc().getDiscovery().isTlsClientCertificateBoundAccessTokens());
        }

        @Bean
        @ConditionalOnMissingBean(name = "casMcpOAuthEndpointConfigurer")
        public CasWebSecurityConfigurer<HttpSecurity> casMcpOAuthEndpointConfigurer(
            final CasConfigurationProperties casProperties,
            final McpServerStreamableHttpProperties mcpServerStreamableHttpProperties,
            @Qualifier(TicketRegistry.BEAN_NAME)
            final ObjectProvider<TicketRegistry> ticketRegistry,
            @Qualifier(ServicesManager.BEAN_NAME)
            final ObjectProvider<ServicesManager> servicesManager,
            @Qualifier(JwtBuilder.ACCESS_TOKEN_JWT_BUILDER_BEAN_NAME)
            final ObjectProvider<JwtBuilder> accessTokenJwtBuilder,
            @Qualifier(PrincipalResolver.BEAN_NAME_PRINCIPAL_RESOLVER)
            final ObjectProvider<PrincipalResolver> principalResolver,
            @Qualifier("oauthProofOfPossessionValidator")
            final ObjectProvider<OAuth20ProofOfPossessionValidator> oauthProofOfPossessionValidator,
            final ConfigurableApplicationContext applicationContext) {
            val endpoint = mcpServerStreamableHttpProperties.getMcpEndpoint();
            val protectedResource = CasMcpProtectedResource.of(casProperties, endpoint);
            return new CasWebSecurityConfigurer<>() {
                @Override
                public List<String> getIgnoredEndpoints() {
                    return List.of(CasMcpProtectedResource.WELL_KNOWN_PATH + Strings.CS.prependIfMissing(endpoint, "/"));
                }

                @Override
                @CanIgnoreReturnValue
                public CasWebSecurityConfigurer<HttpSecurity> configure(final HttpSecurity http) throws Exception {
                    val matcher = PathPatternRequestMatcher.withDefaults().matcher(endpoint);
                    val filter = new CasMcpBearerTokenAuthenticationFilter(matcher, protectedResource,
                        casProperties.getMcp().getOauth(), ticketRegistry.getObject(), servicesManager.getObject(), accessTokenJwtBuilder,
                        principalResolver.getObject(), oauthProofOfPossessionValidator,
                        CasMcpBearerTokenAuthenticationFilter.findOperatorTools(applicationContext.getBeanFactory()));
                    http.addFilterBefore(filter, BasicAuthenticationFilter.class)
                        .exceptionHandling(customizer -> customizer.defaultAuthenticationEntryPointFor(
                            new CasMcpAuthenticationEntryPoint(matcher, protectedResource), matcher));
                    return this;
                }
            };
        }
    }

    @ConditionalOnClass(OAuth20AccessToken.class)
    @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-write", enabledByDefault = false)
    @Configuration(value = "CasMcpOAuthAdministrationConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class CasMcpOAuthAdministrationConfiguration {
        @Bean
        @ConditionalOnMissingBean(name = "casOAuthAdministrationTools")
        public CasOAuthAdministrationTools casOAuthAdministrationTools(
            @Qualifier(TicketRegistry.BEAN_NAME)
            final TicketRegistry ticketRegistry,
            @Qualifier(ServicesManager.BEAN_NAME)
            final ServicesManager servicesManager) {
            return new CasOAuthAdministrationTools(ticketRegistry, servicesManager);
        }
    }

    @ConditionalOnClass(OAuth20AccessToken.class)
    @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-oauth-tokens")
    @Configuration(value = "CasMcpOAuthTokensConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class CasMcpOAuthTokensConfiguration {
        @Bean
        @ConditionalOnMissingBean(name = "casOAuthTools")
        public CasOAuthTools casOAuthTools(
            @Qualifier(TicketRegistry.BEAN_NAME)
            final TicketRegistry ticketRegistry) {
            return new CasOAuthTools(ticketRegistry);
        }
    }

    @ConditionalOnClass(EntityHistoryRepository.class)
    @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-history")
    @Configuration(value = "CasMcpServiceHistoryConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class CasMcpServiceHistoryConfiguration {
        @Bean
        @ConditionalOnMissingBean(name = "casServiceHistoryTools")
        public CasServiceHistoryTools casServiceHistoryTools(
            final ConfigurableApplicationContext applicationContext,
            @Qualifier("objectVersionRepository")
            final ObjectProvider<EntityHistoryRepository> objectVersionRepository,
            @Qualifier(ServicesManager.BEAN_NAME)
            final ServicesManager servicesManager) {
            return new CasServiceHistoryTools(objectVersionRepository, servicesManager,
                new CasServiceManagementTools.RegisteredServiceParser(applicationContext));
        }
    }

    @ConditionalOnClass(SamlResponseBuilder.class)
    @Configuration(value = "CasMcpSaml1Configuration", proxyBeanMethods = false)
    static class CasMcpSaml1Configuration {
        @Bean
        @ConditionalOnMissingBean(name = CasMcpSaml1ResponseRenderer.BEAN_NAME)
        public CasMcpSaml1ResponseRenderer casMcpSaml1ResponseRenderer(
            @Qualifier("samlResponseBuilder")
            final ObjectProvider<SamlResponseBuilder> samlResponseBuilder,
            @Qualifier(OpenSamlConfigBean.DEFAULT_BEAN_NAME)
            final ObjectProvider<OpenSamlConfigBean> openSamlConfigBean) {
            return (service, authentication) -> {
                val builder = samlResponseBuilder.getIfAvailable();
                val configBean = openSamlConfigBean.getIfAvailable();
                if (builder == null || configBean == null) {
                    throw new IllegalStateException("SAML1 validation is not configured");
                }
                val response = builder.createResponse(service.getId(), service);
                val principal = authentication.getPrincipal();
                builder.prepareSuccessfulResponse(Map.of(), response, service, authentication, principal,
                    authentication.getAttributes(), principal.getAttributes());
                return SamlUtils.transformSamlObject(configBean, response).toString();
            };
        }
    }

    @ConditionalOnClass(MultifactorAuthenticationTrustStorage.class)
    @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-trusted-mfa")
    @Configuration(value = "CasMcpTrustedDevicesConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class CasMcpTrustedDevicesConfiguration {
        @Bean
        @ConditionalOnMissingBean(name = "casTrustedDeviceTools")
        public CasTrustedDeviceTools casTrustedDeviceTools(
            @Qualifier(MultifactorAuthenticationTrustStorage.BEAN_NAME)
            final ObjectProvider<MultifactorAuthenticationTrustStorage> mfaTrustEngine) {
            return new CasTrustedDeviceTools(mfaTrustEngine);
        }

        @Bean
        @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-write", enabledByDefault = false)
        @ConditionalOnMissingBean(name = "casTrustedDeviceAdministrationTools")
        public CasTrustedDeviceAdministrationTools casTrustedDeviceAdministrationTools(
            @Qualifier(MultifactorAuthenticationTrustStorage.BEAN_NAME)
            final ObjectProvider<MultifactorAuthenticationTrustStorage> mfaTrustEngine) {
            return new CasTrustedDeviceAdministrationTools(mfaTrustEngine);
        }
    }

    @ConditionalOnClass(SurrogateAuthenticationService.class)
    @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-surrogate")
    @Configuration(value = "CasMcpSurrogateConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class CasMcpSurrogateConfiguration {
        @Bean
        @ConditionalOnMissingBean(name = "casSurrogateTools")
        public CasSurrogateTools casSurrogateTools(
            @Qualifier(SurrogateAuthenticationService.BEAN_NAME)
            final ObjectProvider<SurrogateAuthenticationService> surrogateAuthenticationService,
            @Qualifier(WebApplicationService.BEAN_NAME_FACTORY)
            final ServiceFactory<WebApplicationService> webApplicationServiceFactory) {
            return new CasSurrogateTools(surrogateAuthenticationService, webApplicationServiceFactory);
        }
    }

    @ConditionalOnClass(InterruptInquiryExecutionPlan.class)
    @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-interrupt")
    @Configuration(value = "CasMcpInterruptConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class CasMcpInterruptConfiguration {
        @Bean
        @ConditionalOnMissingBean(name = "casInterruptTools")
        public CasInterruptTools casInterruptTools(
            @Qualifier("casMcpEvaluationContextFactory")
            final CasMcpEvaluationContextFactory casMcpEvaluationContextFactory,
            @Qualifier(InterruptInquirer.BEAN_NAME)
            final ObjectProvider<InterruptInquiryExecutionPlan> interruptInquiryExecutionPlan) {
            return new CasInterruptTools(casMcpEvaluationContextFactory, interruptInquiryExecutionPlan);
        }
    }

    @ConditionalOnClass(AuthenticationRiskEvaluator.class)
    @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-electrofence")
    @Configuration(value = "CasMcpAuthenticationRiskConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class CasMcpAuthenticationRiskConfiguration {
        @Bean
        @ConditionalOnMissingBean(name = "casAuthenticationRiskTools")
        public CasAuthenticationRiskTools casAuthenticationRiskTools(
            final CasConfigurationProperties casProperties,
            @Qualifier("casMcpEvaluationContextFactory")
            final CasMcpEvaluationContextFactory casMcpEvaluationContextFactory,
            @Qualifier("authenticationRiskEvaluator")
            final ObjectProvider<AuthenticationRiskEvaluator> authenticationRiskEvaluator) {
            return new CasAuthenticationRiskTools(casMcpEvaluationContextFactory, authenticationRiskEvaluator, casProperties);
        }
    }

    @ConditionalOnClass(OneTimeTokenCredentialRepository.class)
    @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-otp")
    @Configuration(value = "CasMcpOneTimeTokenConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class CasMcpOneTimeTokenConfiguration {
        @Bean
        @ConditionalOnMissingBean(name = "casOneTimeTokenTools")
        public CasOneTimeTokenTools casOneTimeTokenTools(
            @Qualifier("googleAuthenticatorAccountRegistry")
            final ObjectProvider<OneTimeTokenCredentialRepository> googleAuthenticatorAccountRegistry) {
            return new CasOneTimeTokenTools(googleAuthenticatorAccountRegistry);
        }

        @Bean
        @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-write", enabledByDefault = false)
        @ConditionalOnMissingBean(name = "casOneTimeTokenAdministrationTools")
        public CasOneTimeTokenAdministrationTools casOneTimeTokenAdministrationTools(
            @Qualifier("googleAuthenticatorAccountRegistry")
            final ObjectProvider<OneTimeTokenCredentialRepository> googleAuthenticatorAccountRegistry) {
            return new CasOneTimeTokenAdministrationTools(googleAuthenticatorAccountRegistry);
        }
    }

    @ConditionalOnClass(WebAuthnCredentialRepository.class)
    @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-webauthn")
    @Configuration(value = "CasMcpWebAuthnConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class CasMcpWebAuthnConfiguration {
        @Bean
        @ConditionalOnMissingBean(name = "casWebAuthnTools")
        public CasWebAuthnTools casWebAuthnTools(
            @Qualifier(WebAuthnCredentialRepository.BEAN_NAME)
            final ObjectProvider<WebAuthnCredentialRepository> webAuthnCredentialRepository) {
            return new CasWebAuthnTools(webAuthnCredentialRepository);
        }

        @Bean
        @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-write", enabledByDefault = false)
        @ConditionalOnMissingBean(name = "casWebAuthnAdministrationTools")
        public CasWebAuthnAdministrationTools casWebAuthnAdministrationTools(
            @Qualifier(WebAuthnCredentialRepository.BEAN_NAME)
            final ObjectProvider<WebAuthnCredentialRepository> webAuthnCredentialRepository) {
            return new CasWebAuthnAdministrationTools(webAuthnCredentialRepository);
        }
    }

    @ConditionalOnClass(PasswordlessUserAccountStore.class)
    @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-passwordless")
    @Configuration(value = "CasMcpPasswordlessConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class CasMcpPasswordlessConfiguration {
        @Bean
        @ConditionalOnMissingBean(name = "casPasswordlessTools")
        public CasPasswordlessTools casPasswordlessTools(
            @Qualifier(PasswordlessUserAccountStore.BEAN_NAME)
            final ObjectProvider<PasswordlessUserAccountStore> passwordlessUserAccountStore) {
            return new CasPasswordlessTools(passwordlessUserAccountStore);
        }
    }

    @ConditionalOnClass(DelegatedIdentityProviders.class)
    @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-delegated")
    @Configuration(value = "CasMcpDelegatedAuthenticationConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class CasMcpDelegatedAuthenticationConfiguration {
        @Bean
        @ConditionalOnMissingBean(name = "casDelegatedAuthenticationTools")
        public CasDelegatedAuthenticationTools casDelegatedAuthenticationTools(
            @Qualifier("casMcpEvaluationContextFactory")
            final CasMcpEvaluationContextFactory casMcpEvaluationContextFactory,
            @Qualifier(DelegatedIdentityProviders.BEAN_NAME)
            final ObjectProvider<DelegatedIdentityProviders> delegatedIdentityProviders) {
            return new CasDelegatedAuthenticationTools(casMcpEvaluationContextFactory, delegatedIdentityProviders);
        }
    }

    @ConditionalOnClass(AuthorizableResourceRepository.class)
    @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-heimdall")
    @Configuration(value = "CasMcpHeimdallConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class CasMcpHeimdallConfiguration {
        @Bean
        @ConditionalOnMissingBean(name = "casHeimdallTools")
        public CasHeimdallTools casHeimdallTools(
            @Qualifier(AuthorizableResourceRepository.BEAN_NAME)
            final ObjectProvider<AuthorizableResourceRepository> authorizableResourceRepository,
            @Qualifier("heimdallAuthorizationEngine")
            final ObjectProvider<AuthorizationEngine> heimdallAuthorizationEngine,
            @Qualifier(PrincipalResolver.BEAN_NAME_PRINCIPAL_RESOLVER)
            final PrincipalResolver principalResolver) {
            return new CasHeimdallTools(authorizableResourceRepository, heimdallAuthorizationEngine, principalResolver);
        }
    }

    @ConditionalOnClass(CasConfigurationMetadataRepository.class)
    @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-settings")
    @Configuration(value = "CasMcpSettingsConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class CasMcpSettingsConfiguration {
        @Bean
        @ConditionalOnMissingBean(name = "casSettingResources")
        public CasSettingResources casSettingResources(
            final Environment environment,
            @Qualifier(CasConfigurationMetadataRepository.BEAN_NAME)
            final ObjectProvider<CasConfigurationMetadataRepository> configurationMetadataRepository) {
            return new CasSettingResources(configurationMetadataRepository, environment);
        }

        @Bean
        @ConditionalOnMissingBean(name = "casSettingTools")
        public CasSettingTools casSettingTools(
            @Qualifier(CasConfigurationMetadataRepository.BEAN_NAME)
            final ObjectProvider<CasConfigurationMetadataRepository> configurationMetadataRepository) {
            return new CasSettingTools(configurationMetadataRepository);
        }
    }

    @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-audit")
    @Configuration(value = "CasMcpAuditConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class CasMcpAuditConfiguration {
        @Bean
        @ConditionalOnMissingBean(name = "casMcpAuditor")
        public CasMcpAuditor casMcpAuditor() {
            return new CasMcpAuditor();
        }

        @Bean
        @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
        @ConditionalOnMissingBean(name = "casMcpAuditAdvisor")
        public static Advisor casMcpAuditAdvisor(
            @Qualifier("casMcpAuditor")
            final ObjectProvider<CasMcpAuditor> casMcpAuditor) {
            val pointcut = new ComposablePointcut(new AnnotationMatchingPointcut(null, McpTool.class, true))
                .union(new AnnotationMatchingPointcut(null, McpResource.class, true));
            val advisor = new DefaultPointcutAdvisor(pointcut, new CasMcpAuditInterceptor(casMcpAuditor));
            advisor.setOrder(Ordered.HIGHEST_PRECEDENCE);
            return advisor;
        }

        @Bean
        @ConditionalOnMissingBean(name = "casMcpAuditTrailRecordResolutionPlanConfigurer")
        public AuditTrailRecordResolutionPlanConfigurer casMcpAuditTrailRecordResolutionPlanConfigurer(
            @Qualifier(MessageSanitizer.BEAN_NAME)
            final ObjectProvider<MessageSanitizer> messageSanitizer) {
            return plan -> {
                plan.registerAuditActionResolver(CasMcpAuditor.AUDIT_ACTION_RESOLVER, new CasMcpOperationAuditActionResolver());
                plan.registerAuditResourceResolver(CasMcpAuditor.AUDIT_RESOURCE_RESOLVER,
                    new CasMcpOperationAuditResourceResolver(messageSanitizer.getIfAvailable(MessageSanitizer::disabled)));
            };
        }
    }

    @ConditionalOnClass(PasswordManagementService.class)
    @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-pm")
    @Configuration(value = "CasMcpPasswordManagementConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class CasMcpPasswordManagementConfiguration {
        @Bean
        @ConditionalOnMissingBean(name = "casPasswordManagementTools")
        public CasPasswordManagementTools casPasswordManagementTools(
            @Qualifier(PasswordManagementService.DEFAULT_BEAN_NAME)
            final ObjectProvider<PasswordManagementService> passwordChangeService,
            @Qualifier(PasswordHistoryService.BEAN_NAME)
            final ObjectProvider<PasswordHistoryService> passwordHistoryService) {
            return new CasPasswordManagementTools(passwordChangeService, passwordHistoryService);
        }

        @Bean
        @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-write", enabledByDefault = false)
        @ConditionalOnMissingBean(name = "casPasswordManagementAdministrationTools")
        public CasPasswordManagementAdministrationTools casPasswordManagementAdministrationTools(
            @Qualifier(PasswordManagementService.DEFAULT_BEAN_NAME)
            final ObjectProvider<PasswordManagementService> passwordChangeService) {
            return new CasPasswordManagementAdministrationTools(passwordChangeService);
        }
    }

    @ConditionalOnClass(X509CertificateCredential.class)
    @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-x509")
    @Configuration(value = "CasMcpX509Configuration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class CasMcpX509Configuration {
        @Bean
        @ConditionalOnMissingBean(name = "casX509Tools")
        public CasX509Tools casX509Tools(
            final CasConfigurationProperties casProperties,
            final ConfigurableApplicationContext applicationContext) {
            return new CasX509Tools(casProperties, applicationContext);
        }
    }

    @ConditionalOnClass(JwtBuilder.class)
    @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-token")
    @Configuration(value = "CasMcpJwtTokenConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class CasMcpJwtTokenConfiguration {
        @Bean
        @ConditionalOnMissingBean(name = "casJwtTokenTools")
        public CasJwtTokenTools casJwtTokenTools(
            @Qualifier(JwtBuilder.TICKET_JWT_BUILDER_BEAN_NAME)
            final ObjectProvider<JwtBuilder> tokenTicketJwtBuilder,
            @Qualifier(ServicesManager.BEAN_NAME)
            final ServicesManager servicesManager,
            @Qualifier(WebApplicationService.BEAN_NAME_FACTORY)
            final ServiceFactory<WebApplicationService> webApplicationServiceFactory) {
            return new CasJwtTokenTools(tokenTicketJwtBuilder, servicesManager, webApplicationServiceFactory);
        }
    }

    @ConditionalOnClass(OidcFederationTrustChainResolver.class)
    @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-oidc-federation")
    @Configuration(value = "CasMcpOidcFederationConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class CasMcpOidcFederationConfiguration {
        @Bean
        @ConditionalOnMissingBean(name = "casOidcFederationTools")
        public CasOidcFederationTools casOidcFederationTools(
            final CasConfigurationProperties casProperties,
            @Qualifier(OidcFederationTrustChainResolver.BEAN_NAME)
            final ObjectProvider<OidcFederationTrustChainResolver> oidcFederationTrustChainResolver) {
            return new CasOidcFederationTools(oidcFederationTrustChainResolver, casProperties);
        }
    }

    @ConditionalOnClass(OidcVerifiableCredentialStatusListService.class)
    @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-oidc-vc")
    @Configuration(value = "CasMcpVerifiableCredentialConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class CasMcpVerifiableCredentialConfiguration {
        @Bean
        @ConditionalOnMissingBean(name = "casVerifiableCredentialTools")
        public CasVerifiableCredentialTools casVerifiableCredentialTools(
            @Qualifier(OidcVerifiableCredentialStatusListService.BEAN_NAME)
            final ObjectProvider<OidcVerifiableCredentialStatusListService> statusListService,
            @Qualifier(OidcVerifiableCredentialDeferredIssuanceService.BEAN_NAME)
            final ObjectProvider<OidcVerifiableCredentialDeferredIssuanceService> deferredIssuanceService) {
            return new CasVerifiableCredentialTools(statusListService, deferredIssuanceService);
        }
    }

    @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-groups")
    @Configuration(value = "CasMcpGroupMembershipConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class CasMcpGroupMembershipConfiguration {
        @Bean
        @ConditionalOnMissingBean(name = "casGroupMembershipTools")
        public CasGroupMembershipTools casGroupMembershipTools(
            final ObjectProvider<CasMcpGroupMembershipSource> groupMembershipSources) {
            return new CasGroupMembershipTools(groupMembershipSources);
        }

        @ConditionalOnClass(GrouperFacade.class)
        @Configuration(value = "CasMcpGrouperGroupMembershipConfiguration", proxyBeanMethods = false)
        static class CasMcpGrouperGroupMembershipConfiguration {
            @Bean
            @ConditionalOnMissingBean(name = "casMcpGrouperGroupMembershipSource")
            public CasMcpGroupMembershipSource casMcpGrouperGroupMembershipSource(
                @Qualifier("grouperFacade")
                final ObjectProvider<GrouperFacade> grouperFacade) {
                return new GrouperGroupMembershipSource(grouperFacade);
            }
        }

        @ConditionalOnClass(ScimService.class)
        @Configuration(value = "CasMcpScimGroupMembershipConfiguration", proxyBeanMethods = false)
        static class CasMcpScimGroupMembershipConfiguration {
            @Bean
            @ConditionalOnMissingBean(name = "casMcpScimGroupMembershipSource")
            public CasMcpGroupMembershipSource casMcpScimGroupMembershipSource(
                @Qualifier(ScimService.BEAN_NAME)
                final ObjectProvider<ScimService> scimService) {
                return new ScimGroupMembershipSource(scimService);
            }
        }

        @ConditionalOnClass(SyncopeUtils.class)
        @Configuration(value = "CasMcpSyncopeGroupMembershipConfiguration", proxyBeanMethods = false)
        static class CasMcpSyncopeGroupMembershipConfiguration {
            @Bean
            @ConditionalOnMissingBean(name = "casMcpSyncopeGroupMembershipSource")
            public CasMcpGroupMembershipSource casMcpSyncopeGroupMembershipSource(final CasConfigurationProperties casProperties) {
                return new SyncopeGroupMembershipSource(casProperties);
            }
        }
    }

    @Configuration(value = "CasMcpDiagnosticsConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class CasMcpDiagnosticsConfiguration {
        @Bean
        @ConditionalOnMissingBean(name = "casTicketExpirationTools")
        public CasTicketExpirationTools casTicketExpirationTools(
            final ObjectProvider<ExpirationPolicyBuilder> expirationPolicyBuilders,
            @Qualifier(ServicesManager.BEAN_NAME)
            final ServicesManager servicesManager,
            @Qualifier(WebApplicationService.BEAN_NAME_FACTORY)
            final ServiceFactory<WebApplicationService> webApplicationServiceFactory) {
            return new CasTicketExpirationTools(expirationPolicyBuilders, servicesManager, webApplicationServiceFactory);
        }

        @Bean
        @ConditionalOnMissingBean(name = "casWebflowTools")
        public CasWebflowTools casWebflowTools(final ConfigurableApplicationContext applicationContext) {
            return new CasWebflowTools(applicationContext);
        }

        @Bean
        @ConditionalOnMissingBean(name = "casValidationTools")
        public CasValidationTools casValidationTools(
            final CasConfigurationProperties casProperties,
            final ConfigurableApplicationContext applicationContext,
            @Qualifier("casMcpEvaluationContextFactory")
            final CasMcpEvaluationContextFactory casMcpEvaluationContextFactory,
            @Qualifier(AuditableExecution.AUDITABLE_EXECUTION_REGISTERED_SERVICE_ACCESS)
            final AuditableExecution registeredServiceAccessStrategyEnforcer,
            @Qualifier(AuthenticationAttributeReleasePolicy.BEAN_NAME)
            final ObjectProvider<AuthenticationAttributeReleasePolicy> authenticationAttributeReleasePolicy,
            @Qualifier(CasMcpSaml1ResponseRenderer.BEAN_NAME)
            final ObjectProvider<CasMcpSaml1ResponseRenderer> casMcpSaml1ResponseRenderer) {
            return new CasValidationTools(casMcpEvaluationContextFactory, registeredServiceAccessStrategyEnforcer,
                authenticationAttributeReleasePolicy, casMcpSaml1ResponseRenderer, casProperties, applicationContext);
        }

        @Bean
        @ConditionalOnMissingBean(name = "casGeoLocationTools")
        public CasGeoLocationTools casGeoLocationTools(
            @Qualifier(GeoLocationService.BEAN_NAME)
            final ObjectProvider<GeoLocationService> geoLocationService) {
            return new CasGeoLocationTools(geoLocationService);
        }
    }

    @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AI, module = "mcp-write", enabledByDefault = false)
    @Configuration(value = "CasMcpCoreAdministrationConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class CasMcpCoreAdministrationConfiguration {
        @Bean
        @ConditionalOnMissingBean(name = "casServiceAdministrationTools")
        public CasServiceAdministrationTools casServiceAdministrationTools(
            final ConfigurableApplicationContext applicationContext,
            @Qualifier(ServicesManager.BEAN_NAME)
            final ServicesManager servicesManager) {
            return new CasServiceAdministrationTools(servicesManager, new CasServiceManagementTools.RegisteredServiceParser(applicationContext));
        }

        @Bean
        @ConditionalOnMissingBean(name = "casNotificationAdministrationTools")
        public CasNotificationAdministrationTools casNotificationAdministrationTools(
            @Qualifier(CommunicationsManager.BEAN_NAME)
            final ObjectProvider<CommunicationsManager> communicationsManager,
            @Qualifier(PrincipalResolver.BEAN_NAME_PRINCIPAL_RESOLVER)
            final PrincipalResolver principalResolver) {
            return new CasNotificationAdministrationTools(communicationsManager, principalResolver);
        }

        @Bean
        @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
        @ConditionalOnMissingBean(name = "casMcpConfirmationAdvisor")
        public static Advisor casMcpConfirmationAdvisor() {
            val advisor = new DefaultPointcutAdvisor(CasMcpConfirmationInterceptor.OPERATOR_TOOLS, new CasMcpConfirmationInterceptor());
            advisor.setOrder(AuthorizationInterceptorsOrder.PRE_AUTHORIZE.getOrder() + 1);
            return advisor;
        }
    }

    @Configuration(value = "CasMcpPromptsConfiguration", proxyBeanMethods = false)
    static class CasMcpPromptsConfiguration {
        @Bean
        @ConditionalOnMissingBean(name = "casMcpPrompts")
        public CasMcpPrompts casMcpPrompts() {
            return new CasMcpPrompts();
        }
    }
}
