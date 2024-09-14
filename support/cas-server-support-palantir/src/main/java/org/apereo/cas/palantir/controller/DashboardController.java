package org.apereo.cas.palantir.controller;

import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.palantir.PalantirConstants;
import org.apereo.cas.services.util.RegisteredServiceJsonSerializer;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.springframework.boot.actuate.autoconfigure.endpoint.web.WebEndpointProperties;
import org.springframework.boot.actuate.endpoint.web.EndpointLinksResolver;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * This is {@link DashboardController}.
 *
 * @author Misagh Moayyed
 * @since 7.0.0
 */
@Controller
@RequestMapping(PalantirConstants.URL_PATH_PALANTIR)
@RequiredArgsConstructor
public class DashboardController {
    private final CasConfigurationProperties casProperties;
    private final EndpointLinksResolver endpointLinksResolver;
    private final WebEndpointProperties webEndpointProperties;
    private final ConfigurableApplicationContext applicationContext;

    /**
     * Dashboard home page explicitly defined.
     *
     * @return the model and view
     */
    @GetMapping(path = {StringUtils.EMPTY, "/dashboard", "/", "/dashboard/**"}, produces = MediaType.TEXT_HTML_VALUE)
    public ModelAndView dashboardRoot(final Authentication authentication, final HttpServletRequest request) throws Exception {
        return buildModelAndView(authentication, request);
    }

    private ModelAndView buildModelAndView(final Authentication authentication, final HttpServletRequest request) throws Exception {
        val mav = new ModelAndView("palantir/casPalantirDashboardView");
        mav.addObject("authentication", authentication);
        mav.addObject("casServerPrefix", casProperties.getServer().getPrefix());
        mav.addObject("httpRequestSecure", request.isSecure());
        mav.addObject("httpRequestMethod", request.getMethod());
        val basePath = webEndpointProperties.getBasePath();
        val endpoints = endpointLinksResolver.resolveLinks(basePath);
        val actuatorEndpoints = endpoints
            .entrySet()
            .stream()
            .map(entry -> Pair.of(entry.getKey(), casProperties.getServer().getPrefix() + entry.getValue().getHref()))
            .collect(Collectors.toMap(Pair::getKey, Pair::getValue));
        mav.addObject("actuatorEndpoints", actuatorEndpoints);
        mav.addObject("serviceDefinitions", loadServiceDefinitions());
        return mav;
    }

    private Map<String, List<String>> loadServiceDefinitions() throws IOException {
        val jsonFilesMap = new HashMap<String, List<String>>();
        val serializer = new RegisteredServiceJsonSerializer(applicationContext);
        val resolver = new PathMatchingResourcePatternResolver();
        val resources = resolver.getResources("classpath:service-definitions/**/*.json");

        for (val resource : resources) {
            val contents = new String(FileCopyUtils.copyToByteArray(resource.getInputStream()), StandardCharsets.UTF_8);
            val definition = serializer.from(contents);
            if (definition != null) {
                jsonFilesMap.computeIfAbsent(definition.getFriendlyName(), __ -> new ArrayList<>()).add(contents);
            }
        }
        return jsonFilesMap;
    }
}
