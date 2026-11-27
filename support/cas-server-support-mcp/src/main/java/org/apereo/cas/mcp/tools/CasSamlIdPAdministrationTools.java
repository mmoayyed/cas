package org.apereo.cas.mcp.tools;

import module java.base;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.support.saml.services.SamlRegisteredService;
import org.apereo.cas.support.saml.services.idp.metadata.cache.SamlRegisteredServiceCachingMetadataResolver;
import com.fasterxml.jackson.annotation.JsonInclude;
import io.modelcontextprotocol.server.McpSyncServerExchange;
import lombok.RequiredArgsConstructor;
import lombok.val;
import net.shibboleth.shared.resolver.CriteriaSet;
import org.jspecify.annotations.Nullable;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.criterion.EntityRoleCriterion;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * This is {@link CasSamlIdPAdministrationTools}, available when the SAML2 identity provider is included in the build and
 * the {@code mcp-write} feature is turned on.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@RequiredArgsConstructor
public class CasSamlIdPAdministrationTools {
    private final ServicesManager servicesManager;

    private final ObjectProvider<SamlRegisteredServiceCachingMetadataResolver> metadataResolver;

    /**
     * Drop the cached metadata of a SAML2 service provider and fetch it again.
     *
     * @param entityId the entity id of the service provider
     * @param exchange the MCP exchange, to ask the person at the MCP client to confirm
     * @return whether the metadata resolves again
     */
    @McpTool(description = "Drop the cached metadata of a SAML2 service provider, so that CAS reads it again from its metadata "
        + "source, for instance after the service provider rotated its certificates, and resolve it right away: reports the "
        + "matching registration, whether the metadata resolves and until when it is valid, or the error. Use "
        + "resolveSamlMetadata for the full details.",
        title = "Refresh SAML2 Metadata",
        generateOutputSchema = true,
        annotations = @McpTool.McpAnnotations(readOnlyHint = false, destructiveHint = false,
            idempotentHint = true, openWorldHint = true))
    @PreAuthorize("hasRole('MCP_OPERATOR')")
    public RefreshedMetadata refreshSamlMetadata(
        @McpToolParam(description = "The entity id of the SAML2 service provider")
        final String entityId,
        @Nullable final McpSyncServerExchange exchange) {
        val resolver = metadataResolver.getIfAvailable();
        if (resolver == null) {
            return RefreshedMetadata.refused(entityId, "The SAML2 identity provider is not configured");
        }
        val registeredService = servicesManager.getAllServicesOfType(SamlRegisteredService.class)
            .stream()
            .filter(Objects::nonNull)
            .map(SamlRegisteredService.class::cast)
            .sorted()
            .filter(service -> service.matches(entityId))
            .findFirst()
            .orElse(null);
        if (registeredService == null) {
            return RefreshedMetadata.refused(entityId, "No SAML2 service provider registration matches " + entityId);
        }
        val criteria = new CriteriaSet(new EntityIdCriterion(entityId), new EntityRoleCriterion(SPSSODescriptor.DEFAULT_ELEMENT_NAME));
        try {
            resolver.invalidate(registeredService, criteria);
        } catch (final Throwable e) {
            return new RefreshedMetadata(entityId, registeredService.getId(), registeredService.getName(),
                registeredService.getMetadataLocation(), false, false, null, "The cached metadata cannot be dropped: " + messageOf(e));
        }
        try {
            val result = resolver.resolve(registeredService, criteria);
            val resolved = result != null && result.isResolved();
            val entityDescriptor = resolved ? result.getEntityDescriptor().orElse(null) : null;
            val validUntil = entityDescriptor != null ? entityDescriptor.getValidUntil() : null;
            return new RefreshedMetadata(entityId, registeredService.getId(), registeredService.getName(),
                registeredService.getMetadataLocation(), true, resolved, validUntil != null ? validUntil.toString() : null,
                resolved ? null : "Metadata could not be resolved from " + registeredService.getMetadataLocation());
        } catch (final Throwable e) {
            return new RefreshedMetadata(entityId, registeredService.getId(), registeredService.getName(),
                registeredService.getMetadataLocation(), true, false, null, messageOf(e));
        }
    }

    private static String messageOf(final Throwable e) {
        return Objects.requireNonNullElseGet(e.getMessage(), () -> e.getClass().getSimpleName());
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record RefreshedMetadata(String entityId, @Nullable Long serviceId, @Nullable String serviceName,
                                    @Nullable String metadataLocation, boolean invalidated, boolean resolved,
                                    @Nullable String validUntil, @Nullable String reason) {
        static RefreshedMetadata refused(final String entityId, final String reason) {
            return new RefreshedMetadata(entityId, null, null, null, false, false, null, reason);
        }
    }
}
