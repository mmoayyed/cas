package org.apereo.cas.mcp;

import module java.base;
import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.principal.WebApplicationService;

/**
 * This is {@link CasMcpSaml1ResponseRenderer}, which builds the SAML1 validation response CAS would send an application,
 * when SAML1 is included in the build.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@FunctionalInterface
public interface CasMcpSaml1ResponseRenderer {
    /**
     * The bean name.
     */
    String BEAN_NAME = "casMcpSaml1ResponseRenderer";

    /**
     * Build the SAML1 response, as XML.
     *
     * @param service        the application
     * @param authentication the authentication, whose principal carries the released user id and attributes
     * @return the response XML
     * @throws Exception when the response cannot be built
     */
    String render(WebApplicationService service, Authentication authentication) throws Exception;
}
