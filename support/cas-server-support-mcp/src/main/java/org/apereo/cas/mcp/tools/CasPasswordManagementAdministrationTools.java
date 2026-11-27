package org.apereo.cas.mcp.tools;

import module java.base;
import org.apereo.cas.authentication.credential.BasicIdentifiableCredential;
import org.apereo.cas.pm.PasswordManagementService;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.jspecify.annotations.Nullable;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * This is {@link CasPasswordManagementAdministrationTools}, available when password management is included in the build
 * and the {@code mcp-write} feature is turned on.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@RequiredArgsConstructor
public class CasPasswordManagementAdministrationTools {
    private final ObjectProvider<PasswordManagementService> passwordManagementService;

    /**
     * Unlock an account.
     *
     * @param username the username
     * @return whether the account was unlocked
     */
    @McpTool(description = "Unlock a person's account in the account store behind password management, such as LDAP or a "
        + "database, the way CAS does when the person unlocks it at login. Accounts that are not locked are left as they "
        + "are. Logins throttled by CAS are released with releaseThrottledLogins instead.",
        title = "Unlock Account",
        generateOutputSchema = true,
        annotations = @McpTool.McpAnnotations(readOnlyHint = false, destructiveHint = false,
            idempotentHint = true, openWorldHint = false))
    @PreAuthorize("hasRole('MCP_OPERATOR')")
    public UnlockedAccount unlockAccount(
        @McpToolParam(description = "The username of the person")
        final String username) {
        val service = passwordManagementService.getIfAvailable();
        if (service == null) {
            return new UnlockedAccount(username, false, "Password management is not configured");
        }
        try {
            val unlocked = service.unlockAccount(new BasicIdentifiableCredential(username));
            return new UnlockedAccount(username, unlocked, unlocked ? null : "The account store did not unlock the account");
        } catch (final Throwable e) {
            return new UnlockedAccount(username, false, "The account cannot be unlocked: "
                + Objects.requireNonNullElseGet(e.getMessage(), () -> e.getClass().getSimpleName()));
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record UnlockedAccount(String username, boolean unlocked, @Nullable String reason) {
    }
}
