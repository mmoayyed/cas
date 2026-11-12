package org.apereo.cas.palantir.controller;

import module java.base;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.services.util.RegisteredServiceJsonSerializer;
import org.apereo.cas.test.CasTestExtension;
import lombok.val;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * This is {@link DashboardControllerTests}.
 *
 * @author Misagh Moayyed
 * @since 7.0.0
 */

@SpringBootTest(classes = BasePalantirTests.SharedTestConfiguration.class,
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@EnableConfigurationProperties(CasConfigurationProperties.class)
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
@EnableWebSecurity
@Tag("Web")
@ExtendWith(CasTestExtension.class)
class DashboardControllerTests {
    @Autowired
    @Qualifier("mockMvc")
    private MockMvc mvc;

    @Autowired
    private ConfigurableApplicationContext applicationContext;

    @SuppressWarnings("unchecked")
    private List<Map<String, String>> serviceTemplates() throws Exception {
        val authentication = new UsernamePasswordAuthenticationToken("casuser", "password",
            List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        val model = mvc.perform(get("/palantir/dashboard").with(authentication(authentication)))
            .andExpect(status().isOk())
            .andReturn()
            .getModelAndView()
            .getModel();
        return (List<Map<String, String>>) model.get("serviceTemplates");
    }

    private static void assertFieldsKept(final String path, final JsonNode template, final JsonNode read) {
        template.properties().forEach(entry -> {
            val name = "clientSecret".equals(entry.getKey()) ? "clientSecrets" : entry.getKey();
            assertTrue(read.has(name), () -> path + " dropped " + entry.getKey() + " in " + read);
            if (entry.getValue().isObject() && read.get(name).isObject()) {
                assertFieldsKept(path + '.' + name, entry.getValue(), read.get(name));
            }
        });
    }

    @Test
    void verifyBuiltInTemplatesAreReadWithoutLosingFields() throws Throwable {
        val files = new PathMatchingResourcePatternResolver().getResources("classpath:service-definitions/**/*.json");
        val templates = serviceTemplates().stream().filter(template -> "builtin".equals(template.get("source"))).toList();
        assertEquals(files.length, templates.size());
        assertTrue(templates.stream().map(template -> template.get("type")).distinct().count() >= 5);

        val serializer = new RegisteredServiceJsonSerializer(applicationContext);
        val mapper = JsonMapper.builder().build();
        for (val template : templates) {
            val service = serializer.from(template.get("definition"));
            assertNotNull(service, template.get("definition"));
            assertNotNull(service.getName());
            assertNotNull(service.getDescription());
            assertFieldsKept(service.getName(), mapper.readTree(template.get("definition")), mapper.readTree(serializer.toString(service)));
        }
    }
    
    @Test
    void verifyOperation() throws Throwable {
        val authentication = new UsernamePasswordAuthenticationToken(
            "casuser",
            "password",
            List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
        );
        val model = mvc.perform(get("/palantir/dashboard")
                .with(authentication(authentication)))
            .andExpect(status().isOk())
            .andReturn()
            .getModelAndView()
            .getModel();
        assertNotNull(model.get("casServerPrefix"));
        assertTrue(model.containsKey("authentication"));
        assertTrue(model.containsKey("httpRequestMethod"));
        assertTrue(model.containsKey("httpRequestSecure"));
        assertTrue(model.containsKey("actuatorEndpoints"));
        assertTrue(model.containsKey("actuatorEndpointAccess"));
        assertTrue(model.containsKey("serviceTemplates"));
        assertEquals(Boolean.FALSE, model.get("configurationEncryptionAvailable"));

        mvc.perform(get("/palantir/").with(authentication(authentication))).andExpect(status().isOk());
        mvc.perform(get("/palantir").with(authentication(authentication))).andExpect(status().isOk());

    }

    @Test
    void verifySession() throws Throwable {
        val authentication = new UsernamePasswordAuthenticationToken(
            "casuser",
            "password",
            List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
        );
        val session = new MockHttpSession();
        session.setAttribute(
            HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
            SecurityContextHolder.createEmptyContext()
        );

        mvc.perform(get("/palantir/dashboard/session")
            .with(authentication(authentication))
            .session(session)).andExpect(status().isOk());
        SecurityContextHolder.clearContext();
        mvc.perform(get("/palantir/dashboard/session"))
            .andExpect(status().is3xxRedirection());
    }

    @Nested
    @TestPropertySource(properties = "cas.standalone.configuration-security.psw=Q7M9w4NjYnBxb2#mW")
    class ConfigurationEncryptionTests {
        @Test
        void verifyEncryptionIsAvailable() throws Throwable {
            val authentication = new UsernamePasswordAuthenticationToken("casuser", "password",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
            val model = mvc.perform(get("/palantir/dashboard").with(authentication(authentication)))
                .andExpect(status().isOk())
                .andReturn()
                .getModelAndView()
                .getModel();
            assertEquals(Boolean.TRUE, model.get("configurationEncryptionAvailable"));
        }
    }

    @Nested
    @TestPropertySource(properties = {
        "management.endpoints.web.exposure.include=health,info",
        "management.endpoint.health.access=READ_ONLY",
        "management.endpoint.info.access=UNRESTRICTED"
    })
    class EndpointAccessTests {
        @Test
        void verifyAccessLevelsReachTheDashboard() throws Throwable {
            val authentication = new UsernamePasswordAuthenticationToken("casuser", "password",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
            val model = mvc.perform(get("/palantir/dashboard").with(authentication(authentication)))
                .andExpect(status().isOk())
                .andReturn()
                .getModelAndView()
                .getModel();
            val access = (Map<?, ?>) model.get("actuatorEndpointAccess");
            assertNotNull(access);
            assertEquals("READ_ONLY", access.get("health"));
            assertEquals("UNRESTRICTED", access.get("info"));
        }
    }

    @Nested
    @TestPropertySource(properties = {
        "CasFeatureModule.Palantir.cas-authentication.enabled=true",
        "cas.palantir.cas-authentication.required-attribute-name=memberOf",
        "cas.palantir.cas-authentication.required-attribute-value=admin",
        "cas.monitor.endpoints.endpoint.info.access=AUTHENTICATED"
    })
    class CasAuthenticationTests {
        @Autowired
        @Qualifier("springSecurityFilterChain")
        private FilterChainProxy springSecurityFilterChain;

        @Test
        void verifyCasLoginIsLimitedToPalantir() throws Throwable {
            mvc.perform(get("/palantir/dashboard"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/cas/login?service=**"));

            val entryPoint = springSecurityFilterChain.getFilterChains()
                .stream()
                .flatMap(chain -> chain.getFilters().stream())
                .filter(ExceptionTranslationFilter.class::isInstance)
                .map(ExceptionTranslationFilter.class::cast)
                .findFirst()
                .orElseThrow()
                .getAuthenticationEntryPoint();
            val request = new MockHttpServletRequest("GET", "/actuator/info");
            request.addHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
            val response = new MockHttpServletResponse();
            entryPoint.commence(request, response, new InsufficientAuthenticationException("none"));
            assertNull(response.getRedirectedUrl());
            assertEquals(HttpStatus.UNAUTHORIZED.value(), response.getStatus());
            assertTrue(String.valueOf(response.getHeader(HttpHeaders.WWW_AUTHENTICATE)).startsWith("Basic"));
        }
    }

    @Nested
    @TestPropertySource(properties = "cas.palantir.templates-directory=${java.io.tmpdir}/palantir-shared-templates")
    class SharedTemplatesTests {
        private final Path directory = Path.of(System.getProperty("java.io.tmpdir"), "palantir-shared-templates");

        @BeforeEach
        void writeTemplates() throws Exception {
            Files.createDirectories(directory);
            Files.writeString(directory.resolve("intranet.json"), """
                {
                  "@class": "org.apereo.cas.services.CasRegisteredService",
                  "serviceId": "^https://intranet.example.org/.*",
                  "name": "Intranet",
                  "description": "Our intranet applications"
                }
                """);
            Files.writeString(directory.resolve("broken.json"), "{ \"@class\": \"org.apereo.cas.services.CasRegisteredService\", ");
            Files.writeString(directory.resolve("unknown.json"), """
                { "@class": "org.example.UnknownRegisteredService", "serviceId": "x", "name": "Unknown" }
                """);
            Files.writeString(directory.resolve("notes.txt"), "not a template");
        }

        @Test
        void verifySharedTemplatesAreOfferedAndUnreadableOnesSkipped() throws Throwable {
            val shared = serviceTemplates().stream().filter(template -> "shared".equals(template.get("source"))).toList();
            assertEquals(1, shared.size());
            assertEquals("org.apereo.cas.services.CasRegisteredService", shared.getFirst().get("type"));
            assertTrue(shared.getFirst().get("definition").contains("Our intranet applications"));

            Files.writeString(directory.resolve("portal.json"), """
                { "@class": "org.apereo.cas.services.CasRegisteredService", "serviceId": "^https://portal.example.org/.*", "name": "Portal" }
                """);
            assertEquals(2, serviceTemplates().stream().filter(template -> "shared".equals(template.get("source"))).count());
        }
    }

    @Nested
    @TestPropertySource(properties = "cas.palantir.templates-directory=/does/not/exist")
    class MissingSharedTemplatesTests {
        @Test
        void verifyMissingDirectoryKeepsBuiltInTemplates() throws Throwable {
            val templates = serviceTemplates();
            assertFalse(templates.isEmpty());
            assertTrue(templates.stream().allMatch(template -> "builtin".equals(template.get("source"))));
        }
    }
}
