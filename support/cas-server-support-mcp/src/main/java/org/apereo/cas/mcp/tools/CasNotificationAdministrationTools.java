package org.apereo.cas.mcp.tools;

import module java.base;
import org.apereo.cas.authentication.credential.BasicIdentifiableCredential;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.principal.PrincipalFactoryUtils;
import org.apereo.cas.authentication.principal.PrincipalResolver;
import org.apereo.cas.configuration.model.support.email.EmailProperties;
import org.apereo.cas.configuration.model.support.sms.SmsProperties;
import org.apereo.cas.notifications.CommunicationsManager;
import org.apereo.cas.notifications.mail.EmailMessageRequest;
import org.apereo.cas.notifications.sms.SmsRequest;
import org.apereo.cas.util.function.FunctionUtils;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.jspecify.annotations.Nullable;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * This is {@link CasNotificationAdministrationTools}, which sends test messages through the email and text message
 * senders of CAS, available when the {@code mcp-write} feature is turned on. Messages only go to the addresses and numbers
 * found in a person's attributes, never to arbitrary recipients, and their text is fixed.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@RequiredArgsConstructor
public class CasNotificationAdministrationTools {
    private static final String SUBJECT = "CAS test message";

    private static final String TEXT = "This is a test message from CAS, sent to check that CAS can reach you. No action is needed.";

    private static final PrincipalFactory PRINCIPAL_FACTORY = PrincipalFactoryUtils.newPrincipalFactory();

    private final ObjectProvider<CommunicationsManager> communicationsManager;

    private final PrincipalResolver principalResolver;

    /**
     * Send a test message to a person.
     *
     * @param username  the username of the person
     * @param channel   email or text message
     * @param from      the sender address or number
     * @param attribute the attribute that holds the recipient, optional
     * @return what was sent
     */
    @McpTool(description = "Send a fixed test message to a person through the email or text message (SMS) sender CAS is "
        + "configured with, to check that CAS can reach people, for instance before relying on email for password resets "
        + "or SMS for one-time codes. The message only goes to the email addresses or phone numbers found in the person's "
        + "attributes (mail or email for email; phone, phoneNumber, telephone or telephoneNumber for SMS, unless another "
        + "attribute is named), never to an arbitrary recipient, and its text cannot be changed. Recipients are masked in the result.",
        title = "Send Test Notification",
        generateOutputSchema = true,
        annotations = @McpTool.McpAnnotations(readOnlyHint = false, destructiveHint = false,
            idempotentHint = false, openWorldHint = true))
    @PreAuthorize("hasRole('MCP_OPERATOR')")
    public SentNotification sendTestNotification(
        @McpToolParam(description = "The username of the person")
        final String username,
        @McpToolParam(description = "EMAIL or SMS")
        final NotificationChannel channel,
        @McpToolParam(description = "The sender: an email address for EMAIL, a phone number or sender id for SMS")
        final String from,
        @McpToolParam(description = "The attribute of the person that holds the recipient, if not one of the usual ones", required = false)
        @Nullable final String attribute) {
        val manager = communicationsManager.getIfAvailable();
        if (manager == null) {
            return SentNotification.refused(username, channel, "Notifications are not configured");
        }
        val enabled = channel == NotificationChannel.EMAIL ? manager.isMailSenderDefined() : manager.isSmsSenderDefined();
        if (!enabled) {
            return SentNotification.refused(username, channel, channel == NotificationChannel.EMAIL
                ? "No email sender is configured" : "No SMS sender is configured");
        }
        val principal = resolvePrincipal(username);
        if (principal == null) {
            return SentNotification.refused(username, channel, "The person cannot be resolved");
        }
        val requestedAttribute = StringUtils.trimToNull(attribute);
        val attributeNames = requestedAttribute != null
            ? List.of(requestedAttribute)
            : channel == NotificationChannel.EMAIL ? new EmailProperties().getAttributeName() : new SmsProperties().getAttributeName();
        val attributeName = attributeNames.stream()
            .filter(name -> principal.getAttributes().containsKey(name))
            .findFirst()
            .orElse(null);
        if (attributeName == null) {
            return SentNotification.refused(username, channel, "The person has none of the attributes " + String.join(", ", attributeNames));
        }
        val recipients = principal.getAttributes().getOrDefault(attributeName, List.of()).stream()
            .filter(Objects::nonNull)
            .map(String::valueOf)
            .filter(StringUtils::isNotBlank)
            .toList();
        if (recipients.isEmpty()) {
            return SentNotification.refused(username, channel, "The attribute " + attributeName + " of the person is empty");
        }
        val sent = channel == NotificationChannel.EMAIL
            ? sendEmail(manager, principal, attributeName, from, recipients)
            : sendSms(manager, principal, attributeName, from, recipients);
        return new SentNotification(username, channel, sent, attributeName,
            recipients.stream().map(recipient -> mask(recipient, channel)).toList(), sent ? null : "The sender did not send the message");
    }

    private static boolean sendEmail(final CommunicationsManager manager, final Principal principal, final String attributeName,
                                     final String from, final List<String> recipients) {
        val properties = new EmailProperties().setFrom(from).setSubject(SUBJECT).setText(TEXT);
        properties.setAttributeName(List.of(attributeName));
        val request = EmailMessageRequest.builder()
            .principal(principal)
            .attribute(attributeName)
            .emailProperties(properties)
            .body(TEXT)
            .to(recipients)
            .locale(Locale.ENGLISH)
            .build();
        return manager.email(request).isSuccess();
    }

    private static boolean sendSms(final CommunicationsManager manager, final Principal principal, final String attributeName,
                                   final String from, final List<String> recipients) {
        val request = SmsRequest.builder()
            .principal(principal)
            .attribute(attributeName)
            .from(from)
            .text(TEXT)
            .to(recipients)
            .build();
        return manager.sms(request);
    }

    private @Nullable Principal resolvePrincipal(final String username) {
        val credential = new BasicIdentifiableCredential(username);
        return FunctionUtils.doAndHandle(() -> principalResolver.resolve(credential,
            Optional.ofNullable(PRINCIPAL_FACTORY.createPrincipal(username)), Optional.empty(), Optional.empty()));
    }

    private static String mask(final String recipient, final NotificationChannel channel) {
        if (channel == NotificationChannel.EMAIL) {
            val at = recipient.indexOf('@');
            return at > 1 ? recipient.charAt(0) + "***" + recipient.substring(at) : "***" + (at >= 0 ? recipient.substring(at) : StringUtils.EMPTY);
        }
        val digits = recipient.replaceAll("\\D", StringUtils.EMPTY);
        return digits.length() > 2 ? "***" + digits.substring(digits.length() - 2) : "***";
    }

    /**
     * How to reach a person.
     */
    public enum NotificationChannel {
        /**
         * Email.
         */
        EMAIL,
        /**
         * Text message.
         */
        SMS
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record SentNotification(String username, NotificationChannel channel, boolean sent, @Nullable String attribute,
                                   @Nullable List<String> recipients, @Nullable String reason) {
        static SentNotification refused(final String username, final NotificationChannel channel, final String reason) {
            return new SentNotification(username, channel, false, null, null, reason);
        }
    }
}
