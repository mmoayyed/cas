package org.apereo.cas.mcp.tools;

import module java.base;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.configuration.model.support.oidc.federation.OidcFederationTrustAnchorProperties;
import org.apereo.cas.oidc.federation.chain.OidcFederationTrustChainResolver;
import org.apereo.cas.services.OidcRegisteredService;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.jspecify.annotations.Nullable;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * This is {@link CasOidcFederationTools}, available when OpenID Federation is included in the build. It resolves the trust
 * chain of a relying party the way automatic registration does, without registering it. Keys are never returned.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@RequiredArgsConstructor
public class CasOidcFederationTools {
    private final ObjectProvider<OidcFederationTrustChainResolver> trustChainResolver;

    private final CasConfigurationProperties casProperties;

    /**
     * Resolve the trust chain of an OpenID Federation relying party.
     *
     * @param entityId the entity id of the relying party
     * @return the registration CAS would make, or why the entity is not trusted
     */
    @McpTool(description = "Resolve the trust chain of an OpenID Federation relying party, given its entity id, the way CAS "
        + "does when the relying party registers automatically: fetch its entity configuration and the subordinate "
        + "statements up to one of the trust anchors CAS trusts, check signatures, trust marks and constraints, apply the "
        + "metadata policies, and report the registration that would result (redirect URIs, scopes, grant types, client "
        + "authentication) or why the entity is not trusted. Nothing is registered. Reports the role of CAS in the "
        + "federation and its trust anchors too.",
        title = "Resolve OpenID Federation Trust Chain",
        generateOutputSchema = true,
        annotations = @McpTool.McpAnnotations(readOnlyHint = true, destructiveHint = false,
            idempotentHint = true, openWorldHint = true))
    @PreAuthorize("hasRole('MCP_ADMIN')")
    public FederationEntity resolveOidcTrustChain(
        @McpToolParam(description = "The entity id of the relying party, an https URL")
        final String entityId) {
        val federation = casProperties.getAuthn().getOidc().getFederation();
        val role = federation.getRole() != null ? federation.getRole().name() : null;
        val trustAnchors = federation.getTrustAnchors().stream()
            .map(OidcFederationTrustAnchorProperties::getEntityId)
            .filter(StringUtils::isNotBlank)
            .sorted()
            .toList();
        val resolver = trustChainResolver.getIfAvailable();
        if (resolver == null) {
            return FederationEntity.refused(entityId, role, trustAnchors, "OpenID Federation is not configured");
        }
        if (!Strings.CI.startsWith(entityId, "https://")) {
            return FederationEntity.refused(entityId, role, trustAnchors, "Entity ids are https URLs");
        }
        try {
            return resolver.resolveTrustChains(entityId)
                .map(service -> new FederationEntity(entityId, role, trustAnchors, true, describe(service), null))
                .orElseGet(() -> FederationEntity.refused(entityId, role, trustAnchors,
                    "No trust chain leads from the entity to a trust anchor CAS trusts, or the chain does not verify"));
        } catch (final Throwable e) {
            return FederationEntity.refused(entityId, role, trustAnchors, "The trust chain cannot be resolved: "
                + Objects.requireNonNullElseGet(e.getMessage(), () -> e.getClass().getSimpleName()));
        }
    }

    private static FederationRegistration describe(final OidcRegisteredService service) {
        return new FederationRegistration(service.getClientId(), service.getName(), service.getServiceId(),
            new TreeSet<>(service.getScopes()).stream().toList(),
            new TreeSet<>(service.getSupportedGrantTypes()).stream().toList(),
            new TreeSet<>(service.getSupportedResponseTypes()).stream().toList(),
            service.getTokenEndpointAuthenticationMethod(), StringUtils.isNotBlank(service.getJwks()));
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record FederationEntity(String entityId, @Nullable String role, List<String> trustAnchors, boolean trusted,
                                   @Nullable FederationRegistration registration, @Nullable String reason) {
        static FederationEntity refused(final String entityId, @Nullable final String role, final List<String> trustAnchors,
                                        final String reason) {
            return new FederationEntity(entityId, role, trustAnchors, false, null, reason);
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record FederationRegistration(@Nullable String clientId, @Nullable String name, @Nullable String redirectUriPattern,
                                         List<String> scopes, List<String> grantTypes, List<String> responseTypes,
                                         @Nullable String tokenEndpointAuthenticationMethod, boolean keysDefined) {
    }
}
