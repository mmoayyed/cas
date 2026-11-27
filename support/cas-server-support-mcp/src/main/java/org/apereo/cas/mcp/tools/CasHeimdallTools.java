package org.apereo.cas.mcp.tools;

import module java.base;
import org.apereo.cas.authentication.credential.BasicIdentifiableCredential;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.principal.PrincipalFactoryUtils;
import org.apereo.cas.authentication.principal.PrincipalResolver;
import org.apereo.cas.heimdall.AuthorizationRequest;
import org.apereo.cas.heimdall.authorizer.repository.AuthorizableResourceRepository;
import org.apereo.cas.heimdall.authorizer.resource.AuthorizableResource;
import org.apereo.cas.heimdall.authorizer.resource.policy.ResourceAuthorizationPolicy;
import org.apereo.cas.heimdall.authzen.AuthZenAction;
import org.apereo.cas.heimdall.authzen.AuthZenResource;
import org.apereo.cas.heimdall.authzen.AuthZenSubject;
import org.apereo.cas.heimdall.engine.AuthorizationEngine;
import org.apereo.cas.util.function.FunctionUtils;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.jspecify.annotations.Nullable;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * This is {@link CasHeimdallTools}, available when the Heimdall authorization engine is included in the build.
 * Policies are reported by type only, since their definitions can carry connection details and credentials,
 * and resource properties by name only.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@RequiredArgsConstructor
public class CasHeimdallTools {
    private static final PrincipalFactory PRINCIPAL_FACTORY = PrincipalFactoryUtils.newPrincipalFactory();

    private final ObjectProvider<AuthorizableResourceRepository> authorizableResourceRepository;

    private final ObjectProvider<AuthorizationEngine> authorizationEngine;

    private final PrincipalResolver principalResolver;

    /**
     * Ask Heimdall whether a person may act on a resource.
     *
     * @param username     the username of the person
     * @param namespace    the namespace of an HTTP resource
     * @param method       the HTTP method
     * @param uri          the URI of an HTTP resource
     * @param resourceType the AuthZEN resource type
     * @param resourceId   the AuthZEN resource id
     * @param action       the AuthZEN action
     * @return the decision
     */
    @McpTool(description = "Ask Heimdall, the CAS authorization engine, whether a person may act on a resource, with the "
        + "person's attributes as CAS resolves them now: either an HTTP resource, by namespace, method and URI, or an AuthZEN "
        + "resource, by resource type, resource id and action. Returns the decision, the reason (no matching resource, "
        + "no policies, a policy denied, or the person could not be resolved) and the message of the denying policy.",
        title = "Check Authorization",
        generateOutputSchema = true,
        annotations = @McpTool.McpAnnotations(readOnlyHint = true, destructiveHint = false,
            idempotentHint = true, openWorldHint = true))
    @PreAuthorize("hasRole('MCP_ADMIN')")
    public AuthorizationCheck checkAuthorization(
        @McpToolParam(description = "The username of the person")
        final String username,
        @McpToolParam(description = "The namespace of the HTTP resource", required = false)
        final @Nullable String namespace,
        @McpToolParam(description = "The HTTP method, such as GET", required = false)
        final @Nullable String method,
        @McpToolParam(description = "The URI of the HTTP resource", required = false)
        final @Nullable String uri,
        @McpToolParam(description = "The AuthZEN resource type", required = false)
        final @Nullable String resourceType,
        @McpToolParam(description = "The AuthZEN resource id", required = false)
        final @Nullable String resourceId,
        @McpToolParam(description = "The AuthZEN action, such as can_read", required = false)
        final @Nullable String action) {
        val engine = authorizationEngine.getIfAvailable();
        if (engine == null) {
            return AuthorizationCheck.refused(username, "Heimdall is not configured");
        }
        val authZen = StringUtils.isNoneBlank(resourceType, action);
        if (!authZen && StringUtils.isAnyBlank(namespace, method, uri)) {
            return AuthorizationCheck.refused(username, "Give either a namespace, method and URI, or a resource type and an action");
        }
        val credential = new BasicIdentifiableCredential(username);
        val principal = FunctionUtils.doAndHandle(() -> principalResolver.resolve(credential,
            Optional.ofNullable(PRINCIPAL_FACTORY.createPrincipal(username)), Optional.empty(), Optional.empty()));
        if (principal == null) {
            return AuthorizationCheck.refused(username, "The person cannot be resolved");
        }
        val builder = AuthorizationRequest.builder().principal(principal);
        if (authZen) {
            builder.subject(AuthZenSubject.builder().type("user").id(username).properties(new HashMap<>()).build())
                .resource(AuthZenResource.builder().type(resourceType).id(Objects.requireNonNullElse(resourceId, StringUtils.EMPTY)).properties(new HashMap<>()).build())
                .action(AuthZenAction.builder().name(action).properties(new HashMap<>()).build());
        } else {
            builder.namespace(namespace).method(StringUtils.upperCase(method)).uri(uri);
        }
        val response = engine.authorize(builder.build());
        return new AuthorizationCheck(username, response.getDecision(), response.getStatus().value(),
            response.getReason() != null ? response.getReason().name() : null, StringUtils.trimToNull(response.getMessage()), null);
    }

    /**
     * Find the resources Heimdall protects in a namespace. Policy definitions and property values are never returned.
     *
     * @param namespace the namespace
     * @return the resources, or the known namespaces
     */
    @McpTool(description = "Find the resources Heimdall protects in a namespace: the URI pattern and HTTP method, or the "
        + "AuthZEN resource type, resource id pattern and actions, whether every policy must grant, the types of the "
        + "policies attached and the names of the resource properties. Policy definitions and property values are never "
        + "returned. Without a namespace, or for an unknown one, the known namespaces are listed.",
        title = "Find Authorizable Resources",
        generateOutputSchema = true,
        annotations = @McpTool.McpAnnotations(readOnlyHint = true, destructiveHint = false,
            idempotentHint = true, openWorldHint = false))
    @PreAuthorize("hasRole('MCP_ADMIN')")
    public AuthorizableResources findAuthorizableResources(
        @McpToolParam(description = "The Heimdall namespace", required = false)
        final @Nullable String namespace) {
        val repository = authorizableResourceRepository.getIfAvailable();
        if (repository == null) {
            return new AuthorizableResources(namespace, 0, List.of(), null, "Heimdall is not configured");
        }
        val resources = StringUtils.isBlank(namespace) ? List.<AuthorizableResource>of() : repository.find(namespace);
        if (resources.isEmpty()) {
            val known = new TreeSet<>(repository.findAll().keySet()).stream().toList();
            return new AuthorizableResources(namespace, 0, List.of(), known,
                StringUtils.isNotBlank(namespace) ? "No resources are found in namespace " + namespace : null);
        }
        val summaries = resources
            .stream()
            .sorted(Comparator.comparingLong(AuthorizableResource::getId))
            .map(CasHeimdallTools::summarize)
            .toList();
        return new AuthorizableResources(namespace, summaries.size(), summaries, null, null);
    }

    private static AuthorizableResourceSummary summarize(final AuthorizableResource resource) {
        return new AuthorizableResourceSummary(resource.getId(),
            resource.getPattern() != null ? resource.getPattern().pattern() : null,
            resource.getMethod(), resource.getResourceType(),
            resource.getResourceIdPattern() != null ? resource.getResourceIdPattern().pattern() : null,
            new TreeSet<>(Objects.requireNonNullElseGet(resource.getActions(), Set::<String>of)).stream().toList(),
            resource.isEnforceAllPolicies(),
            Objects.requireNonNullElseGet(resource.getPolicies(), List::<ResourceAuthorizationPolicy>of)
                .stream()
                .map(policy -> AopUtils.getTargetClass(policy).getSimpleName())
                .toList(),
            new TreeSet<>(Objects.requireNonNullElseGet(resource.getProperties(), Map::<String, Object>of).keySet()).stream().toList());
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record AuthorizationCheck(String username, boolean authorized, int status, @Nullable String decisionReason,
                                     @Nullable String message, @Nullable String reason) {
        static AuthorizationCheck refused(final String username, final String reason) {
            return new AuthorizationCheck(username, false, 0, null, null, reason);
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record AuthorizableResources(@Nullable String namespace, int count, List<AuthorizableResourceSummary> resources,
                                        @Nullable List<String> knownNamespaces, @Nullable String reason) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record AuthorizableResourceSummary(long id, @Nullable String pattern, @Nullable String method, @Nullable String resourceType,
                                              @Nullable String resourceIdPattern, List<String> actions, boolean enforceAllPolicies,
                                              List<String> policies, List<String> propertyNames) {
    }
}
