package org.apereo.cas.mcp.groups;

import module java.base;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.mcp.CasMcpGroupMembershipSource;
import org.apereo.cas.syncope.SyncopeUtils;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.apache.commons.lang3.StringUtils;

/**
 * This is {@link SyncopeGroupMembershipSource}, which reads the groups of a person from Apache Syncope, with the settings
 * CAS uses to read attributes from Syncope.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@RequiredArgsConstructor
public class SyncopeGroupMembershipSource implements CasMcpGroupMembershipSource {
    private final CasConfigurationProperties casProperties;

    @Override
    public String getName() {
        return "Apache Syncope";
    }

    @Override
    public Optional<List<String>> findGroups(final String username) {
        val properties = casProperties.getAuthn().getAttributeRepository().getSyncope();
        if (StringUtils.isBlank(properties.getUrl())) {
            return Optional.empty();
        }
        val groups = SyncopeUtils.syncopeUserGroupsSearch(properties, username)
            .stream()
            .flatMap(attributes -> attributes.values().stream())
            .flatMap(List::stream)
            .filter(Objects::nonNull)
            .map(String::valueOf)
            .distinct()
            .toList();
        return Optional.of(groups);
    }
}
