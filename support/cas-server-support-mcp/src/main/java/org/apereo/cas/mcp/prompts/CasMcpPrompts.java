package org.apereo.cas.mcp.prompts;

import module java.base;
import io.modelcontextprotocol.spec.McpSchema;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.jspecify.annotations.Nullable;
import org.springframework.ai.mcp.annotation.McpArg;
import org.springframework.ai.mcp.annotation.McpPrompt;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * This is {@link CasMcpPrompts}, the prompts the MCP server offers: ready-made instructions that walk an agent through a
 * common troubleshooting or onboarding task with the tools of CAS. Prompts only suggest which tools to call; they change
 * nothing, and the tools they name keep their own role checks.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
public class CasMcpPrompts {
    /**
     * The name of the prompt that diagnoses a failed login.
     */
    public static final String DIAGNOSE_LOGIN_FAILURE = "diagnoseLoginFailure";

    /**
     * The name of the prompt that onboards a SAML2 service provider.
     */
    public static final String ONBOARD_SAML_SERVICE_PROVIDER = "onboardSamlServiceProvider";

    /**
     * The name of the prompt that audits an OpenID Connect client.
     */
    public static final String AUDIT_OIDC_CLIENT = "auditOidcClient";

    private static final String READ_ONLY = "Do not call tools that change CAS unless I ask you to. Tools that are not "
        + "available in this deployment can be skipped; say which ones were skipped.";

    /**
     * Diagnose why a person cannot log into an application.
     *
     * @param username the username
     * @param service  the application URL
     * @return the prompt
     */
    @McpPrompt(name = DIAGNOSE_LOGIN_FAILURE, title = "Diagnose Login Failure",
        description = "Find out why a person cannot log into an application, with the tools of CAS, and suggest a fix.")
    @PreAuthorize("hasRole('MCP_ADMIN')")
    public McpSchema.GetPromptResult diagnoseLoginFailure(
        @McpArg(name = "username", description = "The username of the person who cannot log in", required = true)
        final String username,
        @McpArg(name = "service", description = "The URL of the application, such as the service parameter sent to CAS",
            required = false)
        @Nullable final String service) {
        val application = StringUtils.isNotBlank(service) ? "the application " + service : "an application";
        val text = """
            The person %s cannot log into %s with CAS. Find out why, step by step:
            1. Call describeDeployment to learn what this CAS server runs.
            2. Call findPerson for %s to check that CAS finds the person and resolves their attributes.
            3. Call findThrottledLogins and findAuthenticationEvents for the person to look for locked out or failed attempts,
               and findAuditRecords for recent authentication and ticket events.
            4. Call explainLogin for the person and the application to see which step would stop the login: the registered
               service, access strategy, risk, multifactor authentication, interrupts or attribute release. Follow up with
               evaluateAccess, evaluateMultifactorTriggers or previewAttributeRelease on the step that fails.
            5. Call findSessions for the person to see their current single sign-on sessions.
            Then explain the most likely cause in a few sentences, citing what the tools returned, and suggest the change
            that would fix it, such as a service definition change or releasing throttled logins. %s
            """.formatted(username, application, username, READ_ONLY);
        return prompt("Diagnose why " + username + " cannot log into " + application, text);
    }

    /**
     * Onboard a SAML2 service provider.
     *
     * @param entityId         the entity id of the service provider
     * @param metadataLocation where its metadata is published
     * @return the prompt
     */
    @McpPrompt(name = ONBOARD_SAML_SERVICE_PROVIDER, title = "Onboard SAML2 Service Provider",
        description = "Check the metadata of a SAML2 service provider and draft a CAS service definition for it.")
    @PreAuthorize("hasRole('MCP_ADMIN')")
    public McpSchema.GetPromptResult onboardSamlServiceProvider(
        @McpArg(name = "entityId", description = "The entity id of the SAML2 service provider", required = true)
        final String entityId,
        @McpArg(name = "metadataLocation", description = "Where the metadata of the service provider is published, "
            + "such as a URL", required = false)
        @Nullable final String metadataLocation) {
        val metadata = StringUtils.isNotBlank(metadataLocation)
            ? "Its metadata is published at " + metadataLocation + '.'
            : "Ask me where its metadata is published if no registration has it.";
        val text = """
            I want CAS to act as the SAML2 identity provider for the service provider %s. %s
            1. Call searchServices and findService to check whether a registered service already matches the entity id,
               and resolveSamlMetadata to read its metadata: signing and encryption certificates and their expiry,
               assertion consumer service endpoints, single logout endpoints and requested name id formats.
            2. Call describeDeployment and findAttributeDefinitions to learn which attributes CAS can release.
            3. Draft a registered service definition as JSON with the @class org.apereo.cas.support.saml.services.SamlRegisteredService,
               the entity id as an exact regular expression, the metadata location, a name id format the service provider
               accepts and an attribute release policy that releases only what it needs; leave the id out.
            4. Call validateServiceDefinition with the draft and fix what it reports.
            Show me the definition and what you found in the metadata, such as expiring certificates. Save it with
            saveServiceDefinition only when I ask. %s
            """.formatted(entityId, metadata, READ_ONLY);
        return prompt("Onboard the SAML2 service provider " + entityId, text);
    }

    /**
     * Audit an OpenID Connect client.
     *
     * @param clientId the client id
     * @return the prompt
     */
    @McpPrompt(name = AUDIT_OIDC_CLIENT, title = "Audit OpenID Connect Client",
        description = "Review the registration, keys, secrets and tokens of an OpenID Connect or OAuth client and report risks.")
    @PreAuthorize("hasRole('MCP_ADMIN')")
    public McpSchema.GetPromptResult auditOidcClient(
        @McpArg(name = "clientId", description = "The client id of the OpenID Connect or OAuth client", required = true)
        final String clientId) {
        val text = """
            Audit the OpenID Connect or OAuth client %s registered with CAS:
            1. Call findOidcClient for the client: redirect URIs, grant and response types, scopes, client authentication
               method, PKCE, consent, token lifetimes, audience and allowed resources.
            2. Call listJwksKeys and checkOidcClientResource for the resources it uses, and explainExpiration for its
               registered service to see how long its codes and tokens live.
            3. Call findOAuthTokens for the client to see the tokens it holds, and findAuditRecords for its recent activity.
            4. Call previewAttributeRelease for a typical person to see which claims it receives.
            Report the risks you find, most serious first, such as wildcard or plain HTTP redirect URIs, the implicit or
            password grant, a public client without PKCE, client secrets that never expire, long-lived refresh tokens, broad
            scopes or more claims than it needs, with the change that would address each. %s
            """.formatted(clientId, READ_ONLY);
        return prompt("Audit the OpenID Connect client " + clientId, text);
    }

    private static McpSchema.GetPromptResult prompt(final String description, final String text) {
        return new McpSchema.GetPromptResult(description,
            List.of(new McpSchema.PromptMessage(McpSchema.Role.USER, new McpSchema.TextContent(text))));
    }
}
