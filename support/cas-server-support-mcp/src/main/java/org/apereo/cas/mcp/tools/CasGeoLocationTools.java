package org.apereo.cas.mcp.tools;

import module java.base;
import org.apereo.cas.authentication.adaptive.geo.GeoLocationResponse;
import org.apereo.cas.authentication.adaptive.geo.GeoLocationService;
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
 * This is {@link CasGeoLocationTools}, which asks the geolocation service of CAS, used by risk-based authentication and
 * login notifications, where an IP address or a position is.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@RequiredArgsConstructor
public class CasGeoLocationTools {
    private static final Pattern POSITION = Pattern.compile("^\\s*(-?\\d+(?:\\.\\d+)?)\\s*,\\s*(-?\\d+(?:\\.\\d+)?)\\s*$");

    private final ObjectProvider<GeoLocationService> geoLocationService;

    /**
     * Locate an IP address or a position.
     *
     * @param address the IP address, or a position as latitude,longitude
     * @return the location
     */
    @McpTool(description = "Ask the geolocation service CAS uses for risk-based authentication and login notifications, such "
        + "as MaxMind, an IP lookup service or Google Maps, where an IP address is, or what is at a position given as "
        + "latitude,longitude: the latitude, the longitude and the place names it returns.",
        title = "Geolocate Address",
        generateOutputSchema = true,
        annotations = @McpTool.McpAnnotations(readOnlyHint = true, destructiveHint = false,
            idempotentHint = true, openWorldHint = true))
    @PreAuthorize("hasRole('MCP_ADMIN')")
    public GeoLocation geolocateAddress(
        @McpToolParam(description = "An IPv4 or IPv6 address, or a position as latitude,longitude such as 40.71,-74.00")
        final String address) {
        val service = geoLocationService.getIfAvailable();
        if (service == null) {
            return GeoLocation.refused(address, "No geolocation service is configured");
        }
        val value = StringUtils.trimToEmpty(address);
        if (value.isEmpty()) {
            return GeoLocation.refused(address, "An IP address or a position is required");
        }
        try {
            val position = POSITION.matcher(value);
            val response = position.matches()
                ? service.locate(Double.valueOf(position.group(1)), Double.valueOf(position.group(2)))
                : service.locate(value);
            return response != null ? describe(address, response) : GeoLocation.refused(address, "The geolocation service found no location");
        } catch (final Throwable e) {
            return GeoLocation.refused(address, "The geolocation service failed: "
                + Objects.requireNonNullElseGet(e.getMessage(), () -> e.getClass().getSimpleName()));
        }
    }

    private static GeoLocation describe(final String address, final GeoLocationResponse response) {
        return new GeoLocation(address, response.getLatitude(), response.getLongitude(),
            new TreeSet<>(response.getAddresses()).stream().toList(), null);
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record GeoLocation(String address, @Nullable Double latitude, @Nullable Double longitude, @Nullable List<String> places,
                              @Nullable String reason) {
        static GeoLocation refused(final String address, final String reason) {
            return new GeoLocation(address, null, null, null, reason);
        }
    }
}
