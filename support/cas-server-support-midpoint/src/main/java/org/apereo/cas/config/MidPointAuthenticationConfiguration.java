package org.apereo.cas.config;

import org.apereo.cas.authentication.AuthenticationEventExecutionPlanConfigurer;
import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.authentication.CoreAuthenticationUtils;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.principal.PrincipalFactoryUtils;
import org.apereo.cas.authentication.principal.PrincipalNameTransformerUtils;
import org.apereo.cas.authentication.principal.PrincipalResolver;
import org.apereo.cas.authentication.support.password.PasswordEncoderUtils;
import org.apereo.cas.authentication.support.password.PasswordPolicyContext;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.configuration.features.CasFeatureModule;
import org.apereo.cas.midpoint.MidPointAuthenticationHandler;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.util.function.FunctionUtils;
import org.apereo.cas.util.spring.beans.BeanContainer;
import org.apereo.cas.util.spring.boot.ConditionalOnFeatureEnabled;
import lombok.val;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ScopedProxyMode;

/**
 * This is {@link MidPointAuthenticationConfiguration}.
 *
 * @author Misagh Moayyed
 * @since 7.0.0
 */
@EnableConfigurationProperties(CasConfigurationProperties.class)
@ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.Authentication, module = "midpoint")
@AutoConfiguration
public class MidPointAuthenticationConfiguration {
    @ConditionalOnMissingBean(name = "midpointPrincipalFactory")
    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    public PrincipalFactory midpointPrincipalFactory() {
        return PrincipalFactoryUtils.newPrincipalFactory();
    }

    @ConditionalOnMissingBean(name = "midpointAuthenticationHandlers")
    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    public BeanContainer<AuthenticationHandler> midpointAuthenticationHandlers(
        final CasConfigurationProperties casProperties,
        final ConfigurableApplicationContext applicationContext,
        @Qualifier("midpointPrincipalFactory") final PrincipalFactory midpointPrincipalFactory,
        @Qualifier("midpointPasswordPolicyConfiguration") final PasswordPolicyContext midpointPasswordPolicyConfiguration,
        @Qualifier(ServicesManager.BEAN_NAME) final ServicesManager servicesManager) {
        val midpoint = casProperties.getAuthn().getMidpoint();
        val handler = new MidPointAuthenticationHandler(midpoint, servicesManager, midpointPrincipalFactory);
        handler.setState(midpoint.getState());
        handler.setPasswordEncoder(PasswordEncoderUtils.newPasswordEncoder(midpoint.getPasswordEncoder(), applicationContext));
        handler.setPasswordPolicyConfiguration(midpointPasswordPolicyConfiguration);
        val predicate = CoreAuthenticationUtils.newCredentialSelectionPredicate(midpoint.getCredentialCriteria());
        handler.setCredentialSelectionPredicate(predicate);
        val transformer = PrincipalNameTransformerUtils.newPrincipalNameTransformer(midpoint.getPrincipalTransformation());
        handler.setPrincipalNameTransformer(transformer);
        return BeanContainer.of(handler);
    }

    @ConditionalOnMissingBean(name = "midpointAuthenticationEventExecutionPlanConfigurer")
    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    public AuthenticationEventExecutionPlanConfigurer midpointAuthenticationEventExecutionPlanConfigurer(
        final CasConfigurationProperties casProperties,
        @Qualifier("midpointAuthenticationHandlers") final BeanContainer<AuthenticationHandler> midpointAuthenticationHandlers,
        @Qualifier(PrincipalResolver.BEAN_NAME_PRINCIPAL_RESOLVER) final PrincipalResolver defaultPrincipalResolver) {
        return plan -> {
            val midpoint = casProperties.getAuthn().getMidpoint();
            if (midpoint.isDefined()) {
                midpointAuthenticationHandlers.toList().forEach(
                    handler -> plan.registerAuthenticationHandlerWithPrincipalResolver(handler, defaultPrincipalResolver));
            }
        };
    }

    @ConditionalOnMissingBean(name = "midpointPasswordPolicyConfiguration")
    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    public PasswordPolicyContext midpointPasswordPolicyConfiguration() {
        return new PasswordPolicyContext();
    }
}
