package org.apereo.cas.mcp.groups;

import module java.base;
import org.apereo.cas.mcp.CasMcpGroupMembershipSource;
import org.apereo.cas.scim.v2.ScimService;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.springframework.beans.factory.ObjectProvider;

/**
 * This is {@link ScimGroupMembershipSource}, which reads the groups of a person from the SCIM server CAS provisions to.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@RequiredArgsConstructor
public class ScimGroupMembershipSource implements CasMcpGroupMembershipSource {
    private final ObjectProvider<ScimService> scimService;

    @Override
    public String getName() {
        return "SCIM";
    }

    @Override
    public Optional<List<String>> findGroups(final String username) {
        val service = scimService.getIfAvailable();
        if (service == null) {
            return Optional.empty();
        }
        val requestBuilder = service.getScimRequestBuilder(Optional.empty());
        val userResponse = service.findUser(requestBuilder, username);
        if (!userResponse.isSuccess()) {
            throw new IllegalStateException("The SCIM server refused to look up the user");
        }
        val users = userResponse.getResource().getListedResources();
        if (users.isEmpty()) {
            return Optional.of(List.of());
        }
        val memberId = users.getFirst().getId().orElse(null);
        if (memberId == null) {
            return Optional.of(List.of());
        }
        val groupsResponse = service.findUserGroups(requestBuilder, memberId);
        if (!groupsResponse.isSuccess()) {
            throw new IllegalStateException("The SCIM server refused to look up the groups of the user");
        }
        val groups = groupsResponse.getResource().getListedResources()
            .stream()
            .map(group -> group.getDisplayName().or(group::getId).orElse(null))
            .filter(Objects::nonNull)
            .distinct()
            .toList();
        return Optional.of(groups);
    }
}
