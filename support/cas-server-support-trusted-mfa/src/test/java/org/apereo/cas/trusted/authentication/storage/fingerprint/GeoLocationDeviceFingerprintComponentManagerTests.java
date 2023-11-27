package org.apereo.cas.trusted.authentication.storage.fingerprint;

import org.apereo.cas.authentication.adaptive.geo.GeoLocationRequest;
import org.apereo.cas.authentication.adaptive.geo.GeoLocationResponse;
import org.apereo.cas.authentication.adaptive.geo.GeoLocationService;
import org.apereo.cas.trusted.web.flow.fingerprint.GeoLocationDeviceFingerprintComponentManager;
import org.apereo.cas.util.http.HttpRequestUtils;
import lombok.val;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.webflow.context.servlet.ServletExternalContext;
import org.springframework.webflow.test.MockRequestContext;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * This is {@link GeoLocationDeviceFingerprintComponentManagerTests}.
 *
 * @author Misagh Moayyed
 * @since 6.1.0
 */
@Tag("GeoLocation")
class GeoLocationDeviceFingerprintComponentManagerTests {
    @Test
    void verifyGeoLocationDevice() throws Throwable {
        val response = new MockHttpServletResponse();
        val request = new MockHttpServletRequest();
        request.setRemoteAddr("1.2.3.4");
        request.addHeader(HttpRequestUtils.USER_AGENT_HEADER, "TestAgent");
        request.setParameter("geolocation", "40,70,1000,100");

        val geoResp = new GeoLocationResponse();
        geoResp.addAddress("GeoAddress");
        val geoLocationService = mock(GeoLocationService.class);
        when(geoLocationService.locate(anyDouble(), anyDouble())).thenReturn(geoResp);
        when(geoLocationService.locate(any(GeoLocationRequest.class))).thenReturn(geoResp);
        val ex = new GeoLocationDeviceFingerprintComponentManager(geoLocationService);
        val context = new MockRequestContext();
        context.setExternalContext(new ServletExternalContext(new MockServletContext(), request, new MockHttpServletResponse()));
        val result = ex.extractComponent("casuser", request, response);
        assertTrue(result.isPresent());
    }

    @Test
    void verifyNoGeoLocationDevice() throws Throwable {
        val response = new MockHttpServletResponse();
        val request = new MockHttpServletRequest();
        val geoResp = new GeoLocationResponse();
        val geoLocationService = mock(GeoLocationService.class);
        when(geoLocationService.locate(anyDouble(), anyDouble())).thenReturn(geoResp);
        when(geoLocationService.locate(any(GeoLocationRequest.class))).thenReturn(geoResp);
        val ex = new GeoLocationDeviceFingerprintComponentManager(geoLocationService);
        val context = new MockRequestContext();
        context.setExternalContext(new ServletExternalContext(new MockServletContext(), request, new MockHttpServletResponse()));
        val result = ex.extractComponent("casuser", request, response);
        assertFalse(result.isPresent());
    }

}
