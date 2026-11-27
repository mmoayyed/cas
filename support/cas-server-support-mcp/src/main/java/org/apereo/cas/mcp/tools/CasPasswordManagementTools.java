package org.apereo.cas.mcp.tools;

import module java.base;
import org.apereo.cas.pm.PasswordHistoryService;
import org.apereo.cas.pm.PasswordManagementQuery;
import org.apereo.cas.pm.PasswordManagementService;
import org.apereo.cas.pm.impl.history.PasswordHistoryEntity;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.jspecify.annotations.Nullable;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * This is {@link CasPasswordManagementTools}, available when password management is included in the build. Passwords,
 * password history entries and security question answers are never returned; email addresses and phone numbers are masked.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@RequiredArgsConstructor
public class CasPasswordManagementTools {
    private static final int VISIBLE_PHONE_DIGITS = 2;

    private final ObjectProvider<PasswordManagementService> passwordManagementService;

    private final ObjectProvider<PasswordHistoryService> passwordHistoryService;

    /**
     * Find the password management status of an account.
     *
     * @param username the username
     * @return the account status
     */
    @McpTool(description = "Report what password management knows about an account: whether a password reset can reach the "
        + "person by email or text message (with the address and number masked), how many security questions are on file, "
        + "and how many earlier passwords the password history keeps with the date of the latest. Passwords, password "
        + "history entries and security question answers are never returned. Use unlockAccount to unlock a locked account.",
        title = "Find Account Status",
        generateOutputSchema = true,
        annotations = @McpTool.McpAnnotations(readOnlyHint = true, destructiveHint = false,
            idempotentHint = true, openWorldHint = false))
    @PreAuthorize("hasRole('MCP_ADMIN')")
    public AccountStatus findAccountStatus(
        @McpToolParam(description = "The username of the person")
        final String username) {
        val service = passwordManagementService.getIfAvailable();
        if (service == null) {
            return AccountStatus.refused(username, "Password management is not configured");
        }
        val query = PasswordManagementQuery.builder().username(username).build();
        val emails = orElse(() -> service.findEmails(query), Set.<String>of());
        val questions = orElse(() -> service.getSecurityQuestions(query), Map.<String, String>of());
        val historyService = passwordHistoryService.getIfAvailable();
        val history = historyService != null
            ? orElse(() -> List.<PasswordHistoryEntity>copyOf(historyService.fetch(username)), List.<PasswordHistoryEntity>of())
            : List.<PasswordHistoryEntity>of();
        val phone = findPhone(service, query);
        val latestChange = history.stream()
            .map(PasswordHistoryEntity::getRecordDate)
            .filter(Objects::nonNull)
            .max(Comparator.naturalOrder())
            .map(Object::toString)
            .orElse(null);
        val maskedEmails = emails.stream().filter(StringUtils::isNotBlank).map(CasPasswordManagementTools::maskEmail).sorted().toList();
        return new AccountStatus(username, maskedEmails, StringUtils.isNotBlank(phone) ? maskPhone(phone) : null,
            questions.size(), historyService != null ? history.size() : null, latestChange, null);
    }

    private static <T> T orElse(final Lookup<T> supplier, final T fallback) {
        try {
            return supplier.get();
        } catch (final Throwable e) {
            return fallback;
        }
    }

    private static @Nullable String findPhone(final PasswordManagementService service, final PasswordManagementQuery query) {
        try {
            return service.findPhone(query);
        } catch (final Throwable e) {
            return null;
        }
    }

    private static String maskEmail(final String email) {
        val at = email.indexOf('@');
        if (at <= 1) {
            return "***" + (at >= 0 ? email.substring(at) : StringUtils.EMPTY);
        }
        return email.charAt(0) + "***" + email.substring(at);
    }

    private static String maskPhone(final String phone) {
        val digits = phone.replaceAll("\\D", StringUtils.EMPTY);
        return digits.length() <= VISIBLE_PHONE_DIGITS ? "***" : "***" + digits.substring(digits.length() - VISIBLE_PHONE_DIGITS);
    }

    @FunctionalInterface
    private interface Lookup<T> {
        /**
         * Look up a value.
         *
         * @return the value
         * @throws Throwable when the account store cannot be read
         */
        T get() throws Throwable;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record AccountStatus(String username, @Nullable List<String> emails, @Nullable String phone, int securityQuestions,
                                @Nullable Integer passwordHistory, @Nullable String latestPasswordChange, @Nullable String reason) {
        static AccountStatus refused(final String username, final String reason) {
            return new AccountStatus(username, null, null, 0, null, null, reason);
        }
    }
}
