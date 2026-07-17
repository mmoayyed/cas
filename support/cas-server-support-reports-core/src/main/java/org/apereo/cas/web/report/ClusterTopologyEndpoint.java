package org.apereo.cas.web.report;

import module java.base;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.ha.ClusterMember;
import org.apereo.cas.ha.ClusterTopologyManager;
import org.apereo.cas.util.spring.beans.BeanSupplier;
import org.apereo.cas.web.BaseCasActuatorEndpoint;
import io.swagger.v3.oas.annotations.Operation;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.actuate.endpoint.Access;
import org.springframework.boot.actuate.endpoint.annotation.Endpoint;
import org.springframework.boot.actuate.endpoint.annotation.ReadOperation;
import org.springframework.http.MediaType;

/**
 * This is {@link ClusterTopologyEndpoint}.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@Endpoint(id = "clusterTopology", defaultAccess = Access.NONE)
public class ClusterTopologyEndpoint extends BaseCasActuatorEndpoint {
    private final ObjectProvider<ClusterTopologyManager> managers;

    public ClusterTopologyEndpoint(final CasConfigurationProperties casProperties,
                                   final ObjectProvider<ClusterTopologyManager> managers) {
        super(casProperties);
        this.managers = managers;
    }

    /**
     * Members list.
     *
     * @return the list
     */
    @ReadOperation(produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "This endpoint returns a list of cluster members with details such as ID, status, etc")
    public List<ClusterMember> members() {
        return managers
            .orderedStream()
            .filter(BeanSupplier::isNotProxy)
            .flatMap(manager -> manager.discoverMembers().stream())
            .collect(Collectors.toList());
    }
}
