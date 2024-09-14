package org.apereo.cas.mfa.simple.web.flow;

import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.bucket4j.consumer.BucketConsumer;
import org.apereo.cas.configuration.model.support.mfa.simple.CasSimpleMultifactorAuthenticationProperties;
import org.apereo.cas.mfa.simple.CasSimpleMultifactorAuthenticationProvider;
import org.apereo.cas.mfa.simple.CasSimpleMultifactorTokenCommunicationStrategy;
import org.apereo.cas.mfa.simple.CasSimpleMultifactorTokenCommunicationStrategy.TokenSharingStrategyOptions;
import org.apereo.cas.mfa.simple.ticket.CasSimpleMultifactorAuthenticationTicket;
import org.apereo.cas.mfa.simple.validation.CasSimpleMultifactorAuthenticationService;
import org.apereo.cas.notifications.CommunicationsManager;
import org.apereo.cas.ticket.Ticket;
import org.apereo.cas.util.DigestUtils;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.cas.web.flow.actions.AbstractMultifactorAuthenticationAction;
import org.apereo.cas.web.flow.util.MultifactorAuthenticationWebflowUtils;
import org.apereo.cas.web.support.WebUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.tuple.Pair;
import org.jooq.lambda.Unchecked;
import org.springframework.webflow.action.EventFactorySupport;
import org.springframework.webflow.core.collection.LocalAttributeMap;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * This is {@link CasSimpleMultifactorSendTokenAction}.
 *
 * @author Misagh Moayyed
 * @since 6.0.0
 */
@Slf4j
@RequiredArgsConstructor
public class CasSimpleMultifactorSendTokenAction extends AbstractMultifactorAuthenticationAction<CasSimpleMultifactorAuthenticationProvider> {
    /**
     * Flow scope attribute to track email info in the webflow.
     */
    public static final String FLOW_SCOPE_ATTR_EMAIL_RECIPIENTS = "emailRecipients";
    /**
     * Flow scope attribute to track phone info in the webflow.
     */
    public static final String FLOW_SCOPE_ATTR_SMS_RECIPIENTS = "smsRecipients";

    private static final String MESSAGE_MFA_TOKEN_SENT = "cas.mfa.simple.label.tokensent";

    private static final String MESSAGE_MFA_CONTACT_FAILED_SMS = "cas.mfa.simple.label.contactfailed.sms";
    private static final String MESSAGE_MFA_CONTACT_FAILED_EMAIL = "cas.mfa.simple.label.contactfailed.email";

    protected final CommunicationsManager communicationsManager;

    protected final CasSimpleMultifactorAuthenticationService multifactorAuthenticationService;

    protected final CasSimpleMultifactorAuthenticationProperties properties;

    protected final CasSimpleMultifactorTokenCommunicationStrategy tokenCommunicationStrategy;

    protected final BucketConsumer bucketConsumer;

    protected boolean isNotificationSent(final Principal principal, final Ticket token) {
        return communicationsManager.isNotificationSenderDefined()
            && communicationsManager.notify(principal, "Apereo CAS Token", String.format("Token: %s", token.getId()));
    }

    @Override
    protected Event doPreExecute(final RequestContext requestContext) throws Exception {
        val response = WebUtils.getHttpServletResponseFromExternalWebflowContext(requestContext);
        val authentication = WebUtils.getAuthentication(requestContext);
        val result = bucketConsumer.consume(getThrottledRequestKeyFor(authentication, requestContext));
        result.getHeaders().forEach(response::addHeader);
        return result.isConsumed() ? super.doPreExecute(requestContext) : error();
    }

    @Override
    protected Event doExecuteInternal(final RequestContext requestContext) throws Throwable {
        val authentication = WebUtils.getAuthentication(requestContext);
        val principal = resolvePrincipal(authentication.getPrincipal(), requestContext);
        val token = getOrCreateToken(requestContext, principal);
        LOGGER.debug("Using token [{}] created at [{}]", token.getId(), token.getCreationTime());

        val mapOfAllRecipients = new LinkedHashMap<TokenSharingStrategyOptions, List<String>>();
        val communicationStrategy = tokenCommunicationStrategy.determineStrategy(token);

        var smsSent = false;
        if (communicationStrategy.contains(TokenSharingStrategyOptions.SMS)) {
            val cmd = CasSimpleMultifactorSendSms.of(communicationsManager, properties);
            val recipients = cmd.getSmsRecipients(principal);
            mapOfAllRecipients.put(TokenSharingStrategyOptions.SMS, recipients);

            if (recipients.size() > 1) {
                val selectedSmsRecipients = findSelectedSmsRecipients(requestContext, principal);
                LOGGER.debug("Selected SMS recipients are [{}]", selectedSmsRecipients);
                if (!selectedSmsRecipients.isEmpty()) {
                    smsSent = cmd.send(principal, token, requestContext, selectedSmsRecipients);
                    if (!smsSent) {
                        WebUtils.addErrorMessageToContext(requestContext, MESSAGE_MFA_CONTACT_FAILED_SMS);
                    }
                }
            } else {
                smsSent = cmd.send(principal, token, requestContext);
                if (!smsSent) {
                    WebUtils.addErrorMessageToContext(requestContext, MESSAGE_MFA_CONTACT_FAILED_SMS);
                }
            }
        }


        var emailSent = false;
        if (communicationStrategy.contains(TokenSharingStrategyOptions.EMAIL)) {
            val cmd = CasSimpleMultifactorSendEmail.of(communicationsManager, properties);
            val recipients = cmd.getEmailMessageRecipients(principal);
            mapOfAllRecipients.put(TokenSharingStrategyOptions.EMAIL, recipients);

            if (recipients.size() > 1) {
                val selectedEmailRecipients = findSelectedEmailRecipients(requestContext, principal);
                LOGGER.debug("Selected email recipients are [{}]", selectedEmailRecipients);
                if (!selectedEmailRecipients.isEmpty()) {
                    emailSent = cmd.send(principal, token, selectedEmailRecipients, requestContext).isAnyEmailSent();
                    if (!emailSent) {
                        WebUtils.addErrorMessageToContext(requestContext, MESSAGE_MFA_CONTACT_FAILED_EMAIL);
                    }
                }
            } else {
                emailSent = cmd.send(principal, token, requestContext).isAnyEmailSent();
                if (!emailSent) {
                    WebUtils.addErrorMessageToContext(requestContext, MESSAGE_MFA_CONTACT_FAILED_EMAIL);
                }
            }
        }

        if (!emailSent && !smsSent) {
            if (mapOfAllRecipients.isEmpty()) {
                LOGGER.debug("No recipients found for [{}]", principal.getId());
                return getEventFactorySupport().event(this, CasWebflowConstants.TRANSITION_ID_REGISTER,
                    new LocalAttributeMap<>(Map.of("principal", principal, "authentication", authentication)));
            } else {
                val emailRecipients = mapOfAllRecipients.getOrDefault(TokenSharingStrategyOptions.EMAIL, List.of());
                val smsRecipients = mapOfAllRecipients.getOrDefault(TokenSharingStrategyOptions.SMS, List.of());

                if (emailRecipients.size() > 1 || smsRecipients.size() > 1) {
                    LOGGER.debug("Multiple recipients found for [{}]: [{}]", principal.getId(), mapOfAllRecipients);
                    return buildSelectRecipientsEvent(requestContext, principal, mapOfAllRecipients);
                }
            }
        }

        val notificationSent = communicationStrategy.contains(TokenSharingStrategyOptions.NOTIFICATION) && isNotificationSent(principal, token);
        val phoneCallSent = communicationStrategy.contains(TokenSharingStrategyOptions.PHONE)
            && CasSimpleMultifactorMakePhoneCall.of(communicationsManager, properties).call(principal, token, requestContext);

        if (smsSent || emailSent || notificationSent || phoneCallSent) {
            LOGGER.debug("Successfully submitted token via strategy option [{}] to [{}]", communicationStrategy, principal.getId());
            storeToken(requestContext, token);
            return buildSuccessEvent(token);
        }
        LOGGER.error("Communication strategies failed to submit token [{}] to user", token.getId());
        return error();
    }

    protected List<String> findSelectedEmailRecipients(final RequestContext requestContext, final Principal principal) {
        val recipients = getEmailRecipients(requestContext);
        return findSelectedRecipients(requestContext, recipients);
    }

    protected List<String> findSelectedSmsRecipients(final RequestContext requestContext, final Principal principal) {
        val recipients = getSmsRecipients(requestContext);
        return findSelectedRecipients(requestContext, recipients);
    }

    private static List<String> findSelectedRecipients(final RequestContext requestContext,
                                                       final Map<String, CandidateRecipientAddress> recipients) {
        if (recipients == null || recipients.isEmpty()) {
            LOGGER.debug("No selected SMS recipients are found in the request context");
            return List.of();
        }
        val parameters = requestContext.getRequestParameters().asMap();
        return parameters
            .keySet()
            .stream()
            .filter(recipients::containsKey)
            .map(entry -> recipients.get(entry).contact())
            .filter(Objects::nonNull)
            .collect(Collectors.toList());
    }

    private Event buildSelectRecipientsEvent(final RequestContext requestContext, final Principal principal,
                                             final Map<TokenSharingStrategyOptions, List<String>> recipients) {
        val eventAttributes = new LocalAttributeMap<>();

        val emailRecipients = recipients.get(TokenSharingStrategyOptions.EMAIL);
        if (emailRecipients != null) {
            val emailDomainPattern = Pattern.compile(".{2}@.{2}");
            val validAddresses = emailRecipients
                .stream()
                .map(address -> {
                    val hash = DigestUtils.sha512(address);
                    val obfuscated = emailDomainPattern.matcher(address).replaceAll("****@****");
                    return Pair.of(hash, new CandidateRecipientAddress(TokenSharingStrategyOptions.EMAIL, hash, address, obfuscated));
                })
                .collect(Collectors.toMap(Pair::getKey, Pair::getValue));

            putEmailRecipients(requestContext, validAddresses);
            LOGGER.debug("Multiple emails found for [{}]: [{}]", principal.getId(), validAddresses);
            eventAttributes.put(FLOW_SCOPE_ATTR_EMAIL_RECIPIENTS, validAddresses);
        }

        val smsRecipients = recipients.get(TokenSharingStrategyOptions.SMS);
        if (smsRecipients != null) {
            val phonePattern = Pattern.compile("\\d{4}$");
            val validPhones = smsRecipients
                .stream()
                .map(address -> {
                    val hash = DigestUtils.sha512(address);
                    val obfuscated = phonePattern.matcher(address).replaceAll("******");
                    return Pair.of(hash, new CandidateRecipientAddress(TokenSharingStrategyOptions.SMS, hash, address, obfuscated));
                })
                .collect(Collectors.toMap(Pair::getKey, Pair::getValue));

            putSmsRecipients(requestContext, validPhones);
            LOGGER.debug("Multiple phone numbers found for [{}]: [{}]", principal.getId(), validPhones);
            eventAttributes.put(FLOW_SCOPE_ATTR_SMS_RECIPIENTS, validPhones);
        }

        WebUtils.putPrincipal(requestContext, principal);
        return new EventFactorySupport().event(this, CasWebflowConstants.TRANSITION_ID_SELECT, eventAttributes);
    }

    private static void putSmsRecipients(final RequestContext requestContext, final Map<String, CandidateRecipientAddress> validPhones) {
        requestContext.getFlowScope().put(FLOW_SCOPE_ATTR_SMS_RECIPIENTS, validPhones);
    }

    private static void putEmailRecipients(final RequestContext requestContext, final Map<String, CandidateRecipientAddress> validAddresses) {
        requestContext.getFlowScope().put(FLOW_SCOPE_ATTR_EMAIL_RECIPIENTS, validAddresses);
    }

    private static Map<String, CandidateRecipientAddress> getEmailRecipients(final RequestContext requestContext) {
        return (Map<String, CandidateRecipientAddress>) requestContext.getFlowScope().get(FLOW_SCOPE_ATTR_EMAIL_RECIPIENTS, Map.class);
    }

    private static Map<String, CandidateRecipientAddress> getSmsRecipients(final RequestContext requestContext) {
        return (Map<String, CandidateRecipientAddress>) requestContext.getFlowScope().get(FLOW_SCOPE_ATTR_SMS_RECIPIENTS, Map.class);
    }


    protected Event buildSuccessEvent(final CasSimpleMultifactorAuthenticationTicket token) {
        val attributes = new LocalAttributeMap<Object>("token", token.getId());
        return new EventFactorySupport().event(this, CasWebflowConstants.TRANSITION_ID_SUCCESS, attributes);
    }

    protected void storeToken(final RequestContext requestContext, final CasSimpleMultifactorAuthenticationTicket token) throws Throwable {
        multifactorAuthenticationService.store(token);
        WebUtils.addInfoMessageToContext(requestContext, MESSAGE_MFA_TOKEN_SENT);
        MultifactorAuthenticationWebflowUtils.putSimpleMultifactorAuthenticationToken(requestContext, token);
    }

    protected CasSimpleMultifactorAuthenticationTicket getOrCreateToken(final RequestContext requestContext, final Principal principal) {
        val currentToken = MultifactorAuthenticationWebflowUtils.getSimpleMultifactorAuthenticationToken(requestContext, CasSimpleMultifactorAuthenticationTicket.class);
        return Optional.ofNullable(currentToken)
            .filter(token -> !token.isExpired())
            .orElseGet(Unchecked.supplier(() -> {
                MultifactorAuthenticationWebflowUtils.removeSimpleMultifactorAuthenticationToken(requestContext);
                val service = WebUtils.getService(requestContext);
                return multifactorAuthenticationService.generate(principal, service);
            }));
    }

    private String getThrottledRequestKeyFor(final Authentication authentication,
                                             final RequestContext requestContext) {
        val principal = resolvePrincipal(authentication.getPrincipal(), requestContext);
        return principal.getId();
    }

    public record CandidateRecipientAddress(TokenSharingStrategyOptions option, String hash,
        String contact, String obfuscated) implements Serializable {
    }
}
