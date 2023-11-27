package org.apereo.cas.ticket.serialization;

import org.apereo.cas.config.CasCoreHttpConfiguration;
import org.apereo.cas.config.CasCoreNotificationsConfiguration;
import org.apereo.cas.config.CasCoreServicesConfiguration;
import org.apereo.cas.config.CasCoreTicketCatalogConfiguration;
import org.apereo.cas.config.CasCoreTicketIdGeneratorsConfiguration;
import org.apereo.cas.config.CasCoreTicketsConfiguration;
import org.apereo.cas.config.CasCoreTicketsSerializationConfiguration;
import org.apereo.cas.config.CasCoreUtilConfiguration;
import org.apereo.cas.config.CasCoreWebConfiguration;
import org.apereo.cas.config.CasWebApplicationServiceFactoryConfiguration;
import org.apereo.cas.services.RegisteredServiceTestUtils;
import org.apereo.cas.ticket.InvalidTicketException;
import org.apereo.cas.ticket.Ticket;
import org.apereo.cas.ticket.TicketFactory;
import org.apereo.cas.ticket.TicketGrantingTicket;
import org.apereo.cas.ticket.TicketGrantingTicketFactory;
import org.apereo.cas.ticket.proxy.ProxyTicket;

import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.autoconfigure.RefreshAutoConfiguration;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * This is {@link DefaultTicketStringSerializationManagerTests}.
 *
 * @author Misagh Moayyed
 * @since 6.1.0
 */
@SpringBootTest(classes = {
    RefreshAutoConfiguration.class,
    WebMvcAutoConfiguration.class,
    CasCoreHttpConfiguration.class,
    CasCoreTicketsConfiguration.class,
    CasCoreServicesConfiguration.class,
    CasCoreTicketCatalogConfiguration.class,
    CasCoreTicketsSerializationConfiguration.class,
    CasCoreTicketIdGeneratorsConfiguration.class,
    CasCoreNotificationsConfiguration.class,
    CasCoreUtilConfiguration.class,
    CasCoreWebConfiguration.class,
    CasWebApplicationServiceFactoryConfiguration.class
})
@Tag("Tickets")
class DefaultTicketStringSerializationManagerTests {
    @Autowired
    @Qualifier(TicketSerializationManager.BEAN_NAME)
    private TicketSerializationManager ticketSerializationManager;

    @Autowired
    @Qualifier(TicketFactory.BEAN_NAME)
    private TicketFactory defaultTicketFactory;

    @Test
    void verifyOperation() throws Throwable {
        val factory = (TicketGrantingTicketFactory) this.defaultTicketFactory.get(TicketGrantingTicket.class);
        val ticket = factory.create(RegisteredServiceTestUtils.getAuthentication(),
            RegisteredServiceTestUtils.getService(), TicketGrantingTicket.class);
        val result = ticketSerializationManager.serializeTicket(ticket);
        assertNotNull(result);
        val deserializedTicket = ticketSerializationManager.deserializeTicket(result, TicketGrantingTicket.class);
        assertNotNull(deserializedTicket);

        assertThrows(InvalidTicketException.class, () -> ticketSerializationManager.deserializeTicket(result, ProxyTicket.class));
    }

    @Test
    void verifyBadClass() throws Throwable {
        assertThrows(NullPointerException.class, () -> ticketSerializationManager.serializeTicket(mock(Ticket.class)));
        assertThrows(InvalidTicketException.class, () -> ticketSerializationManager.deserializeTicket(StringUtils.EMPTY, StringUtils.EMPTY));
        assertThrows(IllegalArgumentException.class, () -> ticketSerializationManager.deserializeTicket(StringUtils.EMPTY, "something"));
        assertThrows(NullPointerException.class, () -> ticketSerializationManager.deserializeTicket(StringUtils.EMPTY, mock(Ticket.class).getClass()));
    }
}
