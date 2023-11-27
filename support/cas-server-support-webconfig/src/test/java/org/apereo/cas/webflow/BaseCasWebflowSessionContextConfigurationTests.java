package org.apereo.cas.webflow;

import org.apereo.cas.authentication.CoreAuthenticationTestUtils;
import org.apereo.cas.authentication.DefaultAuthenticationResultBuilder;
import org.apereo.cas.authentication.PrincipalElectionStrategy;
import org.apereo.cas.authentication.principal.SimpleWebApplicationServiceImpl;
import org.apereo.cas.config.CasCookieConfiguration;
import org.apereo.cas.config.CasCoreAuditConfiguration;
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
import org.apereo.cas.config.CasCoreServicesAuthenticationConfiguration;
import org.apereo.cas.config.CasCoreServicesConfiguration;
import org.apereo.cas.config.CasCoreTicketCatalogConfiguration;
import org.apereo.cas.config.CasCoreTicketIdGeneratorsConfiguration;
import org.apereo.cas.config.CasCoreTicketsConfiguration;
import org.apereo.cas.config.CasCoreTicketsSerializationConfiguration;
import org.apereo.cas.config.CasCoreUtilConfiguration;
import org.apereo.cas.config.CasCoreValidationConfiguration;
import org.apereo.cas.config.CasCoreWebConfiguration;
import org.apereo.cas.config.CasCoreWebflowConfiguration;
import org.apereo.cas.config.CasDefaultServiceTicketIdGeneratorsConfiguration;
import org.apereo.cas.config.CasFiltersConfiguration;
import org.apereo.cas.config.CasLoggingConfiguration;
import org.apereo.cas.config.CasMultifactorAuthenticationWebflowConfiguration;
import org.apereo.cas.config.CasPersonDirectoryConfiguration;
import org.apereo.cas.config.CasPersonDirectoryStubConfiguration;
import org.apereo.cas.config.CasPropertiesConfiguration;
import org.apereo.cas.config.CasSupportActionsConfiguration;
import org.apereo.cas.config.CasThemesConfiguration;
import org.apereo.cas.config.CasThymeleafConfiguration;
import org.apereo.cas.config.CasWebAppConfiguration;
import org.apereo.cas.config.CasWebApplicationServiceFactoryConfiguration;
import org.apereo.cas.config.CasWebflowContextConfiguration;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.util.function.FunctionUtils;
import org.apereo.cas.web.flow.actions.BaseCasWebflowAction;
import org.apereo.cas.web.support.WebUtils;
import lombok.val;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.aop.AopAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.cloud.autoconfigure.RefreshAutoConfiguration;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.webflow.context.servlet.ServletExternalContext;
import org.springframework.webflow.core.collection.LocalAttributeMap;
import org.springframework.webflow.execution.Action;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.webflow.executor.FlowExecutor;
import org.springframework.webflow.test.MockRequestContext;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentSkipListSet;
import static org.junit.jupiter.api.Assertions.*;

/**
 * This is {@link BaseCasWebflowSessionContextConfigurationTests}.
 *
 * @author Misagh Moayyed
 * @since 5.0.0
 */
@SpringBootTest(classes = {
    AopAutoConfiguration.class,
    RefreshAutoConfiguration.class,
    WebMvcAutoConfiguration.class,
    CasCoreWebflowConfiguration.class,
    CasWebflowContextConfiguration.class,
    CasThemesConfiguration.class,
    CasThymeleafConfiguration.class,
    CasFiltersConfiguration.class,
    CasPropertiesConfiguration.class,
    CasWebAppConfiguration.class,
    BaseCasWebflowSessionContextConfigurationTests.TestWebflowContextConfiguration.class,
    CasMultifactorAuthenticationWebflowConfiguration.class,
    CasCoreTicketIdGeneratorsConfiguration.class,
    CasDefaultServiceTicketIdGeneratorsConfiguration.class,
    CasWebApplicationServiceFactoryConfiguration.class,
    CasCoreAuthenticationConfiguration.class,
    CasCoreServicesAuthenticationConfiguration.class,
    CasCoreAuthenticationPrincipalConfiguration.class,
    CasCoreAuthenticationPolicyConfiguration.class,
    CasCoreAuthenticationMetadataConfiguration.class,
    CasCoreAuthenticationSupportConfiguration.class,
    CasCoreAuthenticationHandlersConfiguration.class,
    CasCoreHttpConfiguration.class,
    CasCoreTicketsConfiguration.class,
    CasCoreTicketCatalogConfiguration.class,
    CasCoreTicketsSerializationConfiguration.class,
    CasLoggingConfiguration.class,
    CasCoreServicesConfiguration.class,
    CasSupportActionsConfiguration.class,
    CasCoreUtilConfiguration.class,
    CasCoreLogoutConfiguration.class,
    CasCookieConfiguration.class,
    CasCoreWebConfiguration.class,
    CasCoreValidationConfiguration.class,
    CasCoreConfiguration.class,
    CasCoreAuthenticationServiceSelectionStrategyConfiguration.class,
    CasCoreAuditConfiguration.class,
    CasCoreNotificationsConfiguration.class,
    CasPersonDirectoryConfiguration.class,
    CasPersonDirectoryStubConfiguration.class,
    CasCoreMultifactorAuthenticationConfiguration.class
}, properties = "spring.main.allow-bean-definition-overriding=true")
@EnableConfigurationProperties(CasConfigurationProperties.class)
@EnableAspectJAutoProxy(proxyTargetClass = false)
public abstract class BaseCasWebflowSessionContextConfigurationTests {
    private static MockRequestContext getMockRequestContext() {
        val ctx = new MockRequestContext();
        val request = new MockHttpServletRequest();
        val response = new MockHttpServletResponse();
        val sCtx = new MockServletContext();
        ctx.setExternalContext(new ServletExternalContext(sCtx, request, response));
        return ctx;
    }

    @Test
    void verifyExecutorsAreBeans() throws Throwable {
        assertNotNull(getFlowExecutor());
    }

    @Test
    void verifyFlowExecutorByClient() throws Throwable {
        val ctx = getMockRequestContext();
        val map = new LocalAttributeMap<>();
        getFlowExecutor().launchExecution("login", map, ctx.getExternalContext());
    }

    public abstract FlowExecutor getFlowExecutor();

    /**
     * The type Test webflow context configuration.
     */
    @TestConfiguration(value = "testWebflowContextConfiguration", proxyBeanMethods = false)
    static class TestWebflowContextConfiguration {
        private static final String TEST = "test";

        @Autowired
        @Qualifier(PrincipalElectionStrategy.BEAN_NAME)
        private ObjectProvider<PrincipalElectionStrategy> principalElectionStrategy;

        @Bean
        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        public Action testWebflowSerialization() {
            //CHECKSTYLE:OFF
            return new BaseCasWebflowAction() {
                @Override
                protected Event doExecuteInternal(final RequestContext requestContext) {
                    val flowScope = requestContext.getFlowScope();
                    flowScope.put("test", TEST);
                    flowScope.put("test0", Collections.singleton(TEST));
                    flowScope.put("test1", List.of(TEST));
                    flowScope.put("test2", Collections.singletonMap(TEST, TEST));
                    flowScope.put("test3", Arrays.asList(TEST, TEST));
                    flowScope.put("test4", new ConcurrentSkipListSet());
                    flowScope.put("test5", List.of("test1"));
                    flowScope.put("test6", Collections.unmodifiableSet(Collections.singleton(1)));
                    flowScope.put("test7", Collections.unmodifiableMap(new HashMap<>()));
                    flowScope.put("test8", Collections.emptyMap());
                    flowScope.put("test9", new TreeMap<>());
                    flowScope.put("test10", Collections.emptySet());
                    flowScope.put("test11", Collections.emptyList());

                    val service = new SimpleWebApplicationServiceImpl();
                    service.setId(CoreAuthenticationTestUtils.CONST_TEST_URL);
                    service.setOriginalUrl(CoreAuthenticationTestUtils.CONST_TEST_URL);
                    service.setArtifactId(null);

                    return FunctionUtils.doUnchecked(() -> {
                        val authentication = CoreAuthenticationTestUtils.getAuthentication();
                        val authenticationResultBuilder = new DefaultAuthenticationResultBuilder();
                        val principal = CoreAuthenticationTestUtils.getPrincipal();
                        authenticationResultBuilder.collect(authentication);
                        authenticationResultBuilder.collect(CoreAuthenticationTestUtils.getCredentialsWithSameUsernameAndPassword());
                        val authenticationResult = authenticationResultBuilder.build(principalElectionStrategy.getObject(), service);

                        WebUtils.putAuthenticationResultBuilder(authenticationResultBuilder, requestContext);
                        WebUtils.putAuthenticationResult(authenticationResult, requestContext);
                        WebUtils.putPrincipal(requestContext, principal);

                        return success();
                    });
                }
            };
            //CHECKSTYLE:ON
        }
    }
}
