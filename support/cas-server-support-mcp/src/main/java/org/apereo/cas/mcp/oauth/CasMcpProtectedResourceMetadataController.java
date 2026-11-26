package org.apereo.cas.mcp.oauth;

import module java.base;
import org.apereo.cas.oidc.issuer.OidcIssuerService;
import org.apereo.cas.support.oauth.validator.OAuth20ProofOfPossessionValidator;
import com.nimbusds.jose.JWSAlgorithm;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * This is {@link CasMcpProtectedResourceMetadataController}, which publishes the OAuth protected resource metadata
 * (RFC 9728) of the MCP server: the resource identifier, CAS as the authorization server through its OpenID Connect
 * issuer, the supported scopes and how tokens are presented; {@code mcp:write} is listed only when the tools that change
 * CAS are turned on. It also lists the algorithms accepted for DPoP proofs and, when CAS issues them, that tokens bound
 * to a client certificate are accepted. The document is served under the CAS context path, at the well-known path followed
 * by the MCP endpoint path, and clients find it through the {@code resource_metadata} parameter of the challenges.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@RestController("casMcpProtectedResourceMetadataController")
@RequiredArgsConstructor
public class CasMcpProtectedResourceMetadataController {
    private final CasMcpProtectedResource protectedResource;

    private final ObjectProvider<OidcIssuerService> oidcIssuerService;

    private final String resourceName;

    private final boolean writable;

    private final ObjectProvider<OAuth20ProofOfPossessionValidator> proofOfPossessionValidator;

    private final boolean certificateBoundAccessTokens;

    /**
     * Protected resource metadata.
     *
     * @return the metadata document
     */
    @GetMapping(path = CasMcpProtectedResource.WELL_KNOWN_PATH + "${spring.ai.mcp.server.streamable-http.mcp-endpoint:/mcp}",
        produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> getProtectedResourceMetadata() {
        val metadata = new LinkedHashMap<String, Object>();
        metadata.put("resource", protectedResource.resource());
        metadata.put("authorization_servers", List.of(oidcIssuerService.getObject().determineIssuer(Optional.empty())));
        metadata.put("scopes_supported", writable
            ? List.of(CasMcpProtectedResource.SCOPE_READ, CasMcpProtectedResource.SCOPE_WRITE)
            : List.of(CasMcpProtectedResource.SCOPE_READ));
        metadata.put("bearer_methods_supported", List.of("header"));
        proofOfPossessionValidator.ifAvailable(validator -> {
            val algorithms = validator.getAcceptedSigningAlgorithms().stream().map(JWSAlgorithm::getName).toList();
            if (!algorithms.isEmpty()) {
                metadata.put("dpop_signing_alg_values_supported", algorithms);
            }
        });
        if (certificateBoundAccessTokens) {
            metadata.put("tls_client_certificate_bound_access_tokens", Boolean.TRUE);
        }
        metadata.put("resource_name", resourceName);
        return ResponseEntity.ok()
            .cacheControl(CacheControl.maxAge(Duration.ofMinutes(5)))
            .contentType(MediaType.APPLICATION_JSON)
            .body(metadata);
    }
}
