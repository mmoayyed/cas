package org.apereo.cas.mcp.tools;

import module java.base;
import org.apereo.cas.audit.AuditableContext;
import org.apereo.cas.audit.AuditableExecution;
import org.apereo.cas.authentication.DefaultAuthenticationBuilder;
import org.apereo.cas.authentication.principal.PrincipalFactoryUtils;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.mcp.CasMcpEvaluationContextFactory;
import org.apereo.cas.mcp.CasMcpSaml1ResponseRenderer;
import org.apereo.cas.services.RegisteredServiceAttributeReleasePolicyContext;
import org.apereo.cas.services.RegisteredServiceUsernameProviderContext;
import org.apereo.cas.util.function.FunctionUtils;
import org.apereo.cas.validation.AuthenticationAttributeReleasePolicy;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.jspecify.annotations.Nullable;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * This is {@link CasValidationTools}, which previews the ticket validation response an application receives for a person,
 * without a ticket and without a password.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@RequiredArgsConstructor
public class CasValidationTools {
    private final CasMcpEvaluationContextFactory evaluationContextFactory;

    private final AuditableExecution registeredServiceAccessStrategyEnforcer;

    private final ObjectProvider<AuthenticationAttributeReleasePolicy> authenticationAttributeReleasePolicy;

    private final ObjectProvider<CasMcpSaml1ResponseRenderer> saml1ResponseRenderer;

    private final CasConfigurationProperties casProperties;

    private final ConfigurableApplicationContext applicationContext;

    /**
     * Preview the validation response of an application for a person.
     *
     * @param username the username
     * @param service  the application URL
     * @param protocol the protocol, CAS3 by default
     * @return the validation response preview
     */
    @McpTool(description = "Preview what an application would receive when it validates a ticket for a person, without a "
        + "ticket and without the person's password: whether access is allowed, the user id the application sees and, as "
        + "the protocol allows, the released principal attributes and authentication attributes. CAS1 returns the user id "
        + "only; CAS2 adds attributes when CAS answers CAS2 validation with CAS3 attributes; CAS3 returns both; SAML1 "
        + "returns the SAML1 response XML, when SAML1 is included in the build.",
        title = "Preview Validation Response",
        generateOutputSchema = true,
        annotations = @McpTool.McpAnnotations(readOnlyHint = true, destructiveHint = false,
            idempotentHint = true, openWorldHint = false))
    @PreAuthorize("hasRole('MCP_ADMIN')")
    public ValidationPreview previewValidationResponse(
        @McpToolParam(description = "The username of the person")
        final String username,
        @McpToolParam(description = "The application URL, such as the service parameter sent to CAS at login")
        final String service,
        @McpToolParam(description = "The validation protocol: CAS1, CAS2, CAS3 or SAML1; CAS3 by default", required = false)
        @Nullable final ValidationProtocol protocol) {
        val selectedProtocol = Objects.requireNonNullElse(protocol, ValidationProtocol.CAS3);
        val context = evaluationContextFactory.build(username, service);
        val registeredService = context.registeredService();
        if (registeredService == null) {
            return ValidationPreview.refused(selectedProtocol, service, "No registered service matches " + context.service().getId());
        }
        val audit = AuditableContext.builder()
            .service(context.service())
            .registeredService(registeredService)
            .principal(context.principal())
            .build();
        val denial = FunctionUtils.doUnchecked(() -> registeredServiceAccessStrategyEnforcer.execute(audit)).getException();
        if (denial.isPresent()) {
            return ValidationPreview.refused(selectedProtocol, service, "Access is denied: "
                + Objects.requireNonNullElseGet(denial.get().getMessage(), () -> denial.get().getClass().getSimpleName()));
        }
        val releaseContext = RegisteredServiceAttributeReleasePolicyContext.builder()
            .registeredService(registeredService)
            .service(context.service())
            .principal(context.principal())
            .applicationContext(applicationContext)
            .build();
        val attributes = FunctionUtils.doUnchecked(() -> registeredService.getAttributeReleasePolicy().getAttributes(releaseContext));
        val usernameContext = RegisteredServiceUsernameProviderContext.builder()
            .registeredService(registeredService)
            .service(context.service())
            .principal(context.principal())
            .releasingAttributes(attributes)
            .applicationContext(applicationContext)
            .build();
        val user = FunctionUtils.doUnchecked(() -> registeredService.getUsernameAttributeProvider().resolveUsername(usernameContext));
        return switch (selectedProtocol) {
            case CAS1 -> new ValidationPreview(selectedProtocol, service, true, user, null, null, null, null);
            case CAS2 -> casProperties.getView().getCas2().isV3ForwardCompatible()
                ? withAttributes(selectedProtocol, service, user, attributes, context)
                : new ValidationPreview(selectedProtocol, service, true, user, null, null, null, null);
            case CAS3 -> withAttributes(selectedProtocol, service, user, attributes, context);
            case SAML1 -> saml1(service, user, attributes, context);
        };
    }

    private ValidationPreview withAttributes(final ValidationProtocol protocol, final String service, final String user,
                                             final Map<String, List<Object>> attributes,
                                             final CasMcpEvaluationContextFactory.CasMcpEvaluationContext context) {
        val policy = authenticationAttributeReleasePolicy.getIfAvailable(AuthenticationAttributeReleasePolicy::none);
        val authenticationAttributes = policy.getAuthenticationAttributesForRelease(context.authentication(),
            Objects.requireNonNull(context.registeredService()));
        return new ValidationPreview(protocol, service, true, user, new TreeMap<>(attributes), new TreeMap<>(authenticationAttributes), null, null);
    }

    private ValidationPreview saml1(final String service, final String user, final Map<String, List<Object>> attributes,
                                    final CasMcpEvaluationContextFactory.CasMcpEvaluationContext context) {
        val renderer = saml1ResponseRenderer.getIfAvailable();
        if (renderer == null) {
            return ValidationPreview.refused(ValidationProtocol.SAML1, service, "SAML1 is not included in this deployment");
        }
        val principal = FunctionUtils.doUnchecked(() -> Objects.requireNonNull(
            PrincipalFactoryUtils.newPrincipalFactory().createPrincipal(user, attributes)));
        val authentication = DefaultAuthenticationBuilder.newInstance(context.authentication()).setPrincipal(principal).build();
        try {
            val response = renderer.render(context.service(), authentication);
            return new ValidationPreview(ValidationProtocol.SAML1, service, true, user, new TreeMap<>(attributes), null, response, null);
        } catch (final Exception e) {
            return ValidationPreview.refused(ValidationProtocol.SAML1, service, "The SAML1 response cannot be built: "
                + Objects.requireNonNullElseGet(e.getMessage(), () -> e.getClass().getSimpleName()));
        }
    }

    /**
     * The validation protocols an application may use.
     */
    public enum ValidationProtocol {
        /**
         * CAS protocol 1.0, {@code /validate}.
         */
        CAS1,
        /**
         * CAS protocol 2.0, {@code /serviceValidate}.
         */
        CAS2,
        /**
         * CAS protocol 3.0, {@code /p3/serviceValidate}.
         */
        CAS3,
        /**
         * SAML 1.1, {@code /samlValidate}.
         */
        SAML1
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ValidationPreview(ValidationProtocol protocol, String service, boolean allowed, @Nullable String user,
                                    @Nullable Map<String, List<Object>> attributes,
                                    @Nullable Map<String, List<Object>> authenticationAttributes,
                                    @Nullable String samlResponse, @Nullable String reason) {
        static ValidationPreview refused(final ValidationProtocol protocol, final String service, final String reason) {
            return new ValidationPreview(protocol, service, false, null, null, null, null, reason);
        }
    }
}
