package org.apereo.cas.midpoint;

import org.apereo.cas.authentication.AuthenticationHandlerExecutionResult;
import org.apereo.cas.authentication.PreventedException;
import org.apereo.cas.authentication.credential.UsernamePasswordCredential;
import org.apereo.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.configuration.model.support.midpoint.MidPointAuthenticationProperties;
import org.apereo.cas.monitor.Monitorable;
import org.apereo.cas.services.ServicesManager;
import com.evolveum.midpoint.client.impl.prism.RestPrismServiceBuilder;
import com.evolveum.midpoint.prism.path.ItemName;
import com.evolveum.midpoint.schema.constants.SchemaConstants;
import com.evolveum.midpoint.xml.ns._public.common.common_3.UserType;
import com.evolveum.prism.xml.ns._public.types_3.ItemPathType;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import javax.security.auth.login.FailedLoginException;
import javax.xml.namespace.QName;
import java.security.GeneralSecurityException;

/**
 * This is {@link MidPointAuthenticationHandler}.
 *
 * @author Misagh Moayyed
 * @since 7.0.0
 */
@Slf4j
@Monitorable
public class MidPointAuthenticationHandler extends AbstractUsernamePasswordAuthenticationHandler {
    private final MidPointAuthenticationProperties properties;

    public MidPointAuthenticationHandler(final MidPointAuthenticationProperties properties,
                                         final ServicesManager servicesManager,
                                         final PrincipalFactory principalFactory) {
        super(properties.getName(), servicesManager, principalFactory, properties.getOrder());
        this.properties = properties;
    }

    @Override
    protected AuthenticationHandlerExecutionResult authenticateUsernamePasswordInternal(
        final UsernamePasswordCredential credential, final String originalPassword)
        throws GeneralSecurityException, PreventedException {
        try {
            val restService = RestPrismServiceBuilder.create()
                .username(properties.getUsername())
                .password(properties.getPassword())
                .baseUrl(properties.getUrl())
                .build();

            val namePath = new ItemPathType(SchemaConstants.C_NAME);
            val result = restService.users()
                .search()
                .queryFor(UserType.class)
                .item(namePath).eq(credential.getUsername())
                .get();
            System.out.println(result);
            return null;
        } catch (final Exception e) {
            e.printStackTrace();
            throw new FailedLoginException("Could not authenticate account for " + credential.getUsername());
        }
    }
}
