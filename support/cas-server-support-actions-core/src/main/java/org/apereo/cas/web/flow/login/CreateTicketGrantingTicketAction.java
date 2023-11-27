package org.apereo.cas.web.flow.login;

import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.AuthenticationResult;
import org.apereo.cas.authentication.MessageDescriptor;
import org.apereo.cas.authentication.PrincipalException;
import org.apereo.cas.ticket.InvalidTicketException;
import org.apereo.cas.ticket.TicketGrantingTicket;
import org.apereo.cas.util.LoggingUtils;
import org.apereo.cas.util.function.FunctionUtils;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.cas.web.flow.actions.BaseCasWebflowAction;
import org.apereo.cas.web.flow.resolver.impl.CasWebflowEventResolutionConfigurationContext;
import org.apereo.cas.web.support.WebUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.springframework.binding.message.MessageBuilder;
import org.springframework.binding.message.MessageContext;
import org.springframework.webflow.action.EventFactorySupport;
import org.springframework.webflow.core.collection.LocalAttributeMap;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import java.util.Collection;
import java.util.stream.Collectors;

/**
 * Action that handles the {@link TicketGrantingTicket} creation and destruction. If the
 * action is given a {@link TicketGrantingTicket} and one also already exists, the old
 * one is destroyed and replaced with the new one. This action always returns
 * "success".
 *
 * @author Scott Battaglia
 * @since 3.0.0
 */
@Slf4j
@RequiredArgsConstructor
public class CreateTicketGrantingTicketAction extends BaseCasWebflowAction {
    private final CasWebflowEventResolutionConfigurationContext configurationContext;

    private static Collection<MessageDescriptor> calculateAuthenticationWarningMessages(final Authentication authentication,
                                                                                        final MessageContext messageContext) {
        val entries = authentication.getSuccesses().entrySet();
        val messages = entries
            .stream()
            .map(entry -> entry.getValue().getWarnings())
            .filter(entry -> !entry.isEmpty())
            .collect(Collectors.toList());
        messages.add(authentication.getWarnings());

        return messages
            .stream()
            .flatMap(Collection::stream)
            .peek(message -> addMessageDescriptorToMessageContext(messageContext, message))
            .collect(Collectors.toSet());
    }

    protected static void addMessageDescriptorToMessageContext(final MessageContext context, final MessageDescriptor warning) {
        val builder = new MessageBuilder()
            .warning()
            .code(warning.getCode())
            .defaultText(warning.getDefaultMessage())
            .args((Object[]) warning.getParams());
        context.addMessage(builder.build());
    }

    @Override
    protected Event doExecuteInternal(final RequestContext context) throws Exception {
        val service = WebUtils.getService(context);
        val registeredService = WebUtils.getRegisteredService(context);
        val authenticationResultBuilder = WebUtils.getAuthenticationResultBuilder(context);

        LOGGER.trace("Finalizing authentication transactions and issuing ticket-granting ticket");
        val authenticationResult = FunctionUtils.doUnchecked(() -> configurationContext.getAuthenticationSystemSupport()
            .finalizeAllAuthenticationTransactions(authenticationResultBuilder, service));
        LOGGER.trace("Finalizing authentication event...");
        val authentication = buildFinalAuthentication(authenticationResult);
        val ticketGrantingTicket = determineTicketGrantingTicketId(context);
        LOGGER.debug("Creating ticket-granting ticket, potentially based on [{}]", ticketGrantingTicket);
        val tgt = createOrUpdateTicketGrantingTicket(authenticationResult, authentication, ticketGrantingTicket);

        if (registeredService != null && registeredService.getAccessStrategy() != null) {
            WebUtils.putUnauthorizedRedirectUrlIntoFlowScope(context, registeredService.getAccessStrategy().getUnauthorizedRedirectUrl());
        }
        WebUtils.putTicketGrantingTicketInScopes(context, tgt);
        WebUtils.putAuthenticationResult(authenticationResult, context);
        WebUtils.putAuthentication(tgt.getAuthentication(), context);

        LOGGER.trace("Calculating authentication warning messages...");
        val warnings = calculateAuthenticationWarningMessages(tgt.getAuthentication(), context.getMessageContext());
        if (!warnings.isEmpty()) {
            val attributes = new LocalAttributeMap<Object>(CasWebflowConstants.ATTRIBUTE_ID_AUTHENTICATION_WARNINGS, warnings);
            return new EventFactorySupport().event(this, CasWebflowConstants.TRANSITION_ID_SUCCESS_WITH_WARNINGS, attributes);
        }
        return success();
    }

    protected Authentication buildFinalAuthentication(final AuthenticationResult authenticationResult) {
        return authenticationResult.getAuthentication();
    }

    /**
     * Create or update ticket granting ticket ticket granting ticket.
     *
     * @param authenticationResult the authentication result
     * @param authentication       the authentication
     * @param ticketGrantingTicket the ticket granting ticket
     * @return the ticket granting ticket
     */
    protected TicketGrantingTicket createOrUpdateTicketGrantingTicket(final AuthenticationResult authenticationResult,
                                                                      final Authentication authentication, final String ticketGrantingTicket) {
        try {
            if (shouldIssueTicketGrantingTicket(authentication, ticketGrantingTicket)) {
                if (StringUtils.isNotBlank(ticketGrantingTicket)) {
                    LOGGER.trace("Removing existing ticket-granting ticket [{}]", ticketGrantingTicket);
                    configurationContext.getTicketRegistry().deleteTicket(ticketGrantingTicket);
                }

                LOGGER.trace("Attempting to issue a new ticket-granting ticket...");
                return configurationContext.getCentralAuthenticationService().createTicketGrantingTicket(authenticationResult);
            }
            LOGGER.debug("Updating the existing ticket-granting ticket [{}]...", ticketGrantingTicket);
            val tgt = configurationContext.getTicketRegistry().getTicket(ticketGrantingTicket, TicketGrantingTicket.class);
            tgt.getAuthentication().updateAttributes(authentication);
            configurationContext.getTicketRegistry().updateTicket(tgt);
            return tgt;
        } catch (final PrincipalException e) {
            LoggingUtils.error(LOGGER, e);
            throw e;
        } catch (final Throwable e) {
            LoggingUtils.error(LOGGER, e);
            throw new InvalidTicketException(ticketGrantingTicket);
        }
    }

    private String determineTicketGrantingTicketId(final RequestContext context) {
        val request = WebUtils.getHttpServletRequestFromExternalWebflowContext(context);
        val ticketGrantingTicketId = configurationContext.getTicketGrantingTicketCookieGenerator().retrieveCookieValue(request);
        if (StringUtils.isBlank(ticketGrantingTicketId)) {
            return WebUtils.getTicketGrantingTicketId(context);
        }
        return ticketGrantingTicketId;
    }

    private boolean shouldIssueTicketGrantingTicket(final Authentication authentication,
                                                    final String ticketGrantingTicket) throws Exception {
        LOGGER.trace("Located ticket-granting ticket in the context. Retrieving associated authentication");
        val authenticationFromTgt = configurationContext.getTicketRegistrySupport().getAuthenticationFrom(ticketGrantingTicket);

        if (authenticationFromTgt == null) {
            LOGGER.debug("Authentication session associated with [{}] is no longer valid", ticketGrantingTicket);
            if (StringUtils.isNotBlank(ticketGrantingTicket)) {
                configurationContext.getTicketRegistry().deleteTicket(ticketGrantingTicket);
            }
            return true;
        }

        if (authentication.isEqualTo(authenticationFromTgt)) {
            LOGGER.debug("Resulting authentication matches the authentication from context");
            return false;
        }
        LOGGER.debug("Resulting authentication is different from the context");
        return true;
    }
}
