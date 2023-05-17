package org.apereo.cas.support.sms;

import org.apereo.cas.notifications.sms.SmsSender;
import org.apereo.cas.util.LoggingUtils;

import com.vonage.client.VonageClient;
import com.vonage.client.sms.MessageStatus;
import com.vonage.client.sms.messages.TextMessage;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;

/**
 * This is {@link VonageSmsSender}.
 *
 * @author Misagh Moayyed
 * @since 6.0.0
 */
@Slf4j
@Getter
@RequiredArgsConstructor
public class VonageSmsSender implements SmsSender {

    private final VonageClient vonageClient;

    @Override
    public boolean send(final String from, final String to, final String message) {
        try {

            val smsClient = vonageClient.getSmsClient();
            val responses = smsClient.submitMessage(new TextMessage(from, to, message));
            val results = responses.getMessages()
                .stream()
                .filter(res -> res.getStatus() != MessageStatus.OK)
                .toList();
            if (results.isEmpty()) {
                return true;
            }
            results.forEach(res -> LOGGER.error("Text message submission has failed: [{}]", res));
        } catch (final Exception e) {
            LoggingUtils.error(LOGGER, e);
        }
        return false;
    }
}
