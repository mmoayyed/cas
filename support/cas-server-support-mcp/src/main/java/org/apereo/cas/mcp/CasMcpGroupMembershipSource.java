package org.apereo.cas.mcp;

import module java.base;

/**
 * This is {@link CasMcpGroupMembershipSource}, a group system CAS is connected to, such as Grouper, a SCIM server or
 * Apache Syncope, that the MCP server can ask for the groups of a person.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
public interface CasMcpGroupMembershipSource {
    /**
     * The name of the group system.
     *
     * @return the name
     */
    String getName();

    /**
     * Find the groups of a person.
     *
     * @param username the username
     * @return the group names, or empty when the group system is not configured
     * @throws Exception when the group system cannot be reached
     */
    Optional<List<String>> findGroups(String username) throws Exception;
}
