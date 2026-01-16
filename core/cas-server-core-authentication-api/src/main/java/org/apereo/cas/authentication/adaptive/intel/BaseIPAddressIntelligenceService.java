package org.apereo.cas.authentication.adaptive.intel;

import module java.base;
import org.apereo.cas.configuration.model.core.authentication.AdaptiveAuthenticationProperties;
import org.apereo.cas.multitenancy.TenantExtractor;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.jspecify.annotations.Nullable;
import org.springframework.webflow.execution.RequestContext;

/**
 * This is {@link BaseIPAddressIntelligenceService}.
 *
 * @author Misagh Moayyed
 * @since 6.0.0
 */
@RequiredArgsConstructor(access = AccessLevel.PROTECTED)
@SuppressWarnings("NullAway.Init")
public abstract class BaseIPAddressIntelligenceService implements IPAddressIntelligenceService {
    protected final TenantExtractor tenantExtractor;
    protected final AdaptiveAuthenticationProperties adaptiveAuthenticationProperties;

    @Nullable
    private volatile Pattern rejectIpAddressesPattern;

    private static void trackResponseInRequestContext(final RequestContext context,
                                                      @Nullable final IPAddressIntelligenceResponse response) {
        context.getFlowScope().put("ipAddressIntelligenceResponse", response);
    }

    @Override
    public @Nullable IPAddressIntelligenceResponse examine(final RequestContext context, final String clientIpAddress) throws Throwable {
        if (isClientIpAddressRejected(clientIpAddress)) {
            val response = IPAddressIntelligenceResponse.banned();
            trackResponseInRequestContext(context, response);
            return response;
        }
        val response = examineInternal(context, clientIpAddress);
        trackResponseInRequestContext(context, response);
        return response;
    }

    protected abstract @Nullable IPAddressIntelligenceResponse examineInternal(RequestContext context, String clientIpAddress) throws Throwable;

    private boolean isClientIpAddressRejected(final String clientIp) {
        val rejectIpAddresses = adaptiveAuthenticationProperties.getPolicy().getRejectIpAddresses();
        if (StringUtils.isBlank(rejectIpAddresses)) {
            return false;
        }
        var pattern = rejectIpAddressesPattern;
        if (pattern == null) {
            synchronized (this) {
                pattern = rejectIpAddressesPattern;
                if (pattern == null) {
                    pattern = Pattern.compile(rejectIpAddresses);
                    rejectIpAddressesPattern = pattern;
                }
            }
        }
        return pattern.matcher(clientIp).find();
    }
}
