package org.apereo.cas.web.report;

import module java.base;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * This is {@link ClusterTopologyEndpointTests}.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@TestPropertySource(properties = "management.endpoint.clusterTopology.access=UNRESTRICTED")
@Tag("ActuatorEndpoint")
class ClusterTopologyEndpointTests extends AbstractCasEndpointTests {
    @Test
    void verifyOperation() throws Exception {
        mockMvc.perform(get("/actuator/clusterTopology")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk());
    }
}
