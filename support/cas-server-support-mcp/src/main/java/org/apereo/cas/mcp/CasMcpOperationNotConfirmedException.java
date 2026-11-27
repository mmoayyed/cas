package org.apereo.cas.mcp;

import module java.base;

/**
 * This is {@link CasMcpOperationNotConfirmedException}, thrown when the person at the MCP client does not confirm a tool
 * call that changes CAS: they declined or dismissed the request, or the client could not ask them.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
public class CasMcpOperationNotConfirmedException extends RuntimeException {
    @Serial
    private static final long serialVersionUID = 6253086519328047491L;

    public CasMcpOperationNotConfirmedException(final String message) {
        super(message);
    }
}
