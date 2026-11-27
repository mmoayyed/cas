package org.apereo.cas.mcp.tools;

import module java.base;
import org.apereo.cas.oidc.vc.issuer.deferred.OidcVerifiableCredentialDeferredIssuanceService;
import org.apereo.cas.oidc.vc.issuer.status.OidcVerifiableCredentialStatusListService;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.jspecify.annotations.Nullable;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * This is {@link CasVerifiableCredentialTools}, available when OpenID for Verifiable Credential Issuance is included in
 * the build. Credentials and deferred transaction ids are never returned.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@RequiredArgsConstructor
public class CasVerifiableCredentialTools {
    private final ObjectProvider<OidcVerifiableCredentialStatusListService> statusListService;

    private final ObjectProvider<OidcVerifiableCredentialDeferredIssuanceService> deferredIssuanceService;

    /**
     * Find the verifiable credentials issued to a person and their status, and the person's deferred issuance requests.
     *
     * @param username the username
     * @return the credentials and deferred requests
     */
    @McpTool(description = "List the verifiable credentials CAS issued to a person with OpenID for Verifiable Credential "
        + "Issuance: for each, its credential configuration, the wallet client, its status list entry and status (valid, "
        + "revoked or suspended) and when it expires; and the person's deferred issuance requests with their status "
        + "(pending, approved or denied). Credentials and transaction ids are never returned.",
        title = "Find Verifiable Credential Status",
        generateOutputSchema = true,
        annotations = @McpTool.McpAnnotations(readOnlyHint = true, destructiveHint = false,
            idempotentHint = true, openWorldHint = false))
    @PreAuthorize("hasRole('MCP_ADMIN')")
    public VerifiableCredentialStatus findVerifiableCredentialStatus(
        @McpToolParam(description = "The username (principal id) of the person")
        final String username) {
        val statusList = statusListService.getIfAvailable();
        val deferred = deferredIssuanceService.getIfAvailable();
        if (statusList == null && deferred == null) {
            return new VerifiableCredentialStatus(username, List.of(), List.of(), "Verifiable credential issuance is not configured");
        }
        val credentials = statusList == null ? List.<IssuedCredential>of() : statusList.getEntries(username)
            .stream()
            .map(entry -> new IssuedCredential(entry.credentialConfigurationId(), entry.clientId(), entry.statusListId(),
                entry.index(), entry.uri(), entry.status().name(), Instant.ofEpochSecond(entry.expiresAt()).toString()))
            .toList();
        val transactions = deferred == null ? List.<DeferredRequest>of() : deferred.getTransactions(username)
            .stream()
            .map(transaction -> new DeferredRequest(transaction.credentialConfigurationId(), transaction.clientId(),
                transaction.status().name(), Instant.ofEpochSecond(transaction.createdAt()).toString(), transaction.getCredentials()))
            .toList();
        return new VerifiableCredentialStatus(username, credentials, transactions, null);
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record VerifiableCredentialStatus(String username, List<IssuedCredential> credentials, List<DeferredRequest> deferredRequests,
                                             @Nullable String reason) {
    }

    public record IssuedCredential(String credentialConfigurationId, String clientId, String statusListId, long index, String statusListUri,
                                   String status, String expiresAt) {
    }

    public record DeferredRequest(String credentialConfigurationId, String clientId, String status, String createdAt, int credentials) {
    }
}
