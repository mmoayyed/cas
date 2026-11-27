package org.apereo.cas.mcp.tools;

import module java.base;
import org.apereo.cas.mcp.CasMcpGroupMembershipSource;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.jspecify.annotations.Nullable;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * This is {@link CasGroupMembershipTools}, which asks the group systems CAS is connected to for the groups of a person.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@RequiredArgsConstructor
public class CasGroupMembershipTools {
    private static final int MAX_GROUPS = 200;

    private final ObjectProvider<CasMcpGroupMembershipSource> groupMembershipSources;

    /**
     * Find the groups of a person in every group system CAS is connected to.
     *
     * @param username the username
     * @return the groups, per group system
     */
    @McpTool(description = "Ask the group systems CAS is connected to (Grouper, a SCIM server, Apache Syncope) for the groups "
        + "of a person, the way CAS reads them for attributes, access strategies and multifactor triggers. Each group system "
        + "reports the group names (at most " + MAX_GROUPS + "), or why it could not be asked.",
        title = "Find Group Memberships",
        generateOutputSchema = true,
        annotations = @McpTool.McpAnnotations(readOnlyHint = true, destructiveHint = false,
            idempotentHint = true, openWorldHint = true))
    @PreAuthorize("hasRole('MCP_ADMIN')")
    public GroupMemberships findGroupMemberships(
        @McpToolParam(description = "The username of the person")
        final String username) {
        val sources = groupMembershipSources.orderedStream()
            .map(source -> lookup(source, username))
            .flatMap(Optional::stream)
            .toList();
        return new GroupMemberships(username, sources, sources.isEmpty() ? "No group system is configured" : null);
    }

    private static Optional<GroupSource> lookup(final CasMcpGroupMembershipSource source, final String username) {
        try {
            return source.findGroups(username)
                .map(groups -> new GroupSource(source.getName(), groups.size(),
                    groups.stream().sorted().limit(MAX_GROUPS).toList(), null));
        } catch (final Throwable e) {
            return Optional.of(new GroupSource(source.getName(), 0, List.of(),
                Objects.requireNonNullElseGet(e.getMessage(), () -> e.getClass().getSimpleName())));
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record GroupMemberships(String username, List<GroupSource> sources, @Nullable String reason) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record GroupSource(String source, int count, List<String> groups, @Nullable String error) {
    }
}
