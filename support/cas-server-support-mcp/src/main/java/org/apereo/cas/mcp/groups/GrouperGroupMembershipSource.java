package org.apereo.cas.mcp.groups;

import module java.base;
import org.apereo.cas.grouper.GrouperFacade;
import org.apereo.cas.grouper.GrouperGroupField;
import org.apereo.cas.mcp.CasMcpGroupMembershipSource;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.springframework.beans.factory.ObjectProvider;

/**
 * This is {@link GrouperGroupMembershipSource}, which reads the groups of a person from Grouper.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@RequiredArgsConstructor
public class GrouperGroupMembershipSource implements CasMcpGroupMembershipSource {
    private final ObjectProvider<GrouperFacade> grouperFacade;

    @Override
    public String getName() {
        return "Grouper";
    }

    @Override
    public Optional<List<String>> findGroups(final String username) {
        val facade = grouperFacade.getIfAvailable();
        if (facade == null) {
            return Optional.empty();
        }
        val groups = facade.getGroupsForSubjectId(username)
            .stream()
            .filter(result -> result.getWsGroups() != null)
            .flatMap(result -> Arrays.stream(result.getWsGroups()))
            .map(group -> GrouperFacade.getGrouperGroupAttribute(GrouperGroupField.NAME, group))
            .filter(Objects::nonNull)
            .distinct()
            .toList();
        return Optional.of(groups);
    }
}
