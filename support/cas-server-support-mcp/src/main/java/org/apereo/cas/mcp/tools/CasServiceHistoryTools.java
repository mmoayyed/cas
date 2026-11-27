package org.apereo.cas.mcp.tools;

import module java.base;
import org.apereo.cas.services.RegisteredService;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.version.EntityHistoryRepository;
import org.apereo.cas.version.HistoricalEntity;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.jspecify.annotations.Nullable;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.access.prepost.PreAuthorize;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * This is {@link CasServiceHistoryTools}, which reads the change history of registered services, available when service
 * history is included in the build. Secrets are redacted in every version.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@RequiredArgsConstructor
public class CasServiceHistoryTools {
    private static final int DEFAULT_VERSIONS = 20;

    private static final int MAX_VERSIONS = 100;

    private static final int MAX_CHANGES = 200;

    private static final int MAX_VALUE_LENGTH = 300;

    private static final String CURRENT = "current";

    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    private final ObjectProvider<EntityHistoryRepository> entityHistoryRepository;

    private final ServicesManager servicesManager;

    private final CasServiceManagementTools.RegisteredServiceParser registeredServiceParser;

    /**
     * Find the versions of a registered service.
     *
     * @param serviceId the numeric id of the registered service
     * @param limit     the number of versions, newest first
     * @return the versions
     */
    @McpTool(description = "List the saved versions of a registered service (application), newest first: the version id, "
        + "when it was saved and by whom, and the properties that changed from the version before it. Use "
        + "diffServiceVersions with two version ids to see the values that changed.",
        title = "Find Service History",
        generateOutputSchema = true,
        annotations = @McpTool.McpAnnotations(readOnlyHint = true, destructiveHint = false,
            idempotentHint = true, openWorldHint = false))
    @PreAuthorize("hasRole('MCP_ADMIN')")
    public ServiceHistory findServiceHistory(
        @McpToolParam(description = "The numeric id of the registered service")
        final long serviceId,
        @McpToolParam(description = "How many versions to return, newest first; " + DEFAULT_VERSIONS + " by default, at most "
            + MAX_VERSIONS, required = false)
        @Nullable final Integer limit) {
        val repository = entityHistoryRepository.getIfAvailable();
        if (repository == null) {
            return new ServiceHistory(serviceId, 0, List.of(), "Service history is not configured");
        }
        val registeredService = servicesManager.findServiceBy(serviceId);
        if (registeredService == null) {
            return new ServiceHistory(serviceId, 0, List.of(), "No registered service has the id " + serviceId);
        }
        val history = repository.getHistory(registeredService);
        val count = Math.clamp(Objects.requireNonNullElse(limit, DEFAULT_VERSIONS), 1, MAX_VERSIONS);
        val versions = IntStream.range(0, Math.min(count, history.size()))
            .mapToObj(index -> {
                val version = history.get(index);
                val changed = index + 1 < history.size()
                    ? diff(flatten(history.get(index + 1)), flatten(version)).stream().map(ServiceChange::property).toList()
                    : List.<String>of();
                return new ServiceVersion(version.id(), version.date().toString(), version.author(), changed);
            })
            .toList();
        return new ServiceHistory(serviceId, history.size(), versions, history.isEmpty() ? "No history is recorded for this service" : null);
    }

    /**
     * Compare two versions of a registered service.
     *
     * @param serviceId   the numeric id of the registered service
     * @param fromVersion the older version id
     * @param toVersion   the newer version id, or the service as it is saved now
     * @return the changes
     */
    @McpTool(description = "Compare two versions of a registered service (application) and list each property that was added, "
        + "removed or changed, with its old and new value. Versions are the ids returned by findServiceHistory; leave out the "
        + "newer version to compare with the service as it is saved now. Secrets are shown as "
        + CasServiceManagementTools.REDACTED + ". At most " + MAX_CHANGES + " changes are returned.",
        title = "Compare Service Versions",
        generateOutputSchema = true,
        annotations = @McpTool.McpAnnotations(readOnlyHint = true, destructiveHint = false,
            idempotentHint = true, openWorldHint = false))
    @PreAuthorize("hasRole('MCP_ADMIN')")
    public ServiceDiff diffServiceVersions(
        @McpToolParam(description = "The numeric id of the registered service")
        final long serviceId,
        @McpToolParam(description = "The id of the older version, from findServiceHistory")
        final String fromVersion,
        @McpToolParam(description = "The id of the newer version; the service as it is saved now by default", required = false)
        @Nullable final String toVersion) {
        val to = StringUtils.defaultIfBlank(toVersion, CURRENT);
        val repository = entityHistoryRepository.getIfAvailable();
        if (repository == null) {
            return ServiceDiff.refused(serviceId, fromVersion, to, "Service history is not configured");
        }
        val registeredService = servicesManager.findServiceBy(serviceId);
        if (registeredService == null) {
            return ServiceDiff.refused(serviceId, fromVersion, to, "No registered service has the id " + serviceId);
        }
        val history = repository.getHistory(registeredService);
        val older = history.stream().filter(version -> version.id().equals(fromVersion)).findFirst();
        val newer = CURRENT.equals(to)
            ? Optional.of(flatten(registeredService))
            : history.stream().filter(version -> version.id().equals(to)).findFirst().map(this::flatten);
        if (older.isEmpty() || newer.isEmpty()) {
            return ServiceDiff.refused(serviceId, fromVersion, to, "Unknown version; known versions are "
                + history.stream().map(HistoricalEntity::id).collect(Collectors.joining(", ")));
        }
        val changes = diff(flatten(older.get()), newer.get());
        return new ServiceDiff(serviceId, fromVersion, to, changes.size(), changes.stream().limit(MAX_CHANGES).toList(), null);
    }

    private Map<String, String> flatten(final HistoricalEntity version) {
        return version.entity() instanceof final RegisteredService service ? flatten(service) : Map.of();
    }

    private Map<String, String> flatten(final RegisteredService registeredService) {
        val tree = MAPPER.readTree(registeredServiceParser.toString(registeredService));
        CasServiceManagementTools.redact(tree);
        val properties = new TreeMap<String, String>();
        flatten(tree, StringUtils.EMPTY, properties);
        return properties;
    }

    private static void flatten(final JsonNode node, final String path, final Map<String, String> properties) {
        if (node.isObject()) {
            node.properties().forEach(entry -> flatten(entry.getValue(), path.isEmpty() ? entry.getKey() : path + '.' + entry.getKey(), properties));
        } else if (node.isArray()) {
            IntStream.range(0, node.size()).forEach(index -> flatten(node.get(index), path + '[' + index + ']', properties));
        } else {
            properties.put(path, StringUtils.abbreviate(node.isString() ? node.asString() : node.toString(), MAX_VALUE_LENGTH));
        }
    }

    private static List<ServiceChange> diff(final Map<String, String> older, final Map<String, String> newer) {
        val properties = new TreeSet<String>(older.keySet());
        properties.addAll(newer.keySet());
        return properties.stream()
            .filter(property -> !Objects.equals(older.get(property), newer.get(property)))
            .map(property -> new ServiceChange(property,
                !older.containsKey(property) ? ChangeKind.ADDED : !newer.containsKey(property) ? ChangeKind.REMOVED : ChangeKind.CHANGED,
                older.get(property), newer.get(property)))
            .toList();
    }

    /**
     * How a property changed between two versions.
     */
    public enum ChangeKind {
        /**
         * The newer version adds the property.
         */
        ADDED,
        /**
         * The newer version removes the property.
         */
        REMOVED,
        /**
         * The value changed.
         */
        CHANGED
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ServiceHistory(long serviceId, int count, List<ServiceVersion> versions, @Nullable String reason) {
    }

    public record ServiceVersion(String version, String savedAt, String author, List<String> changedProperties) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ServiceDiff(long serviceId, String fromVersion, String toVersion, int count, List<ServiceChange> changes,
                              @Nullable String reason) {
        static ServiceDiff refused(final long serviceId, final String fromVersion, final String toVersion, final String reason) {
            return new ServiceDiff(serviceId, fromVersion, toVersion, 0, List.of(), reason);
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ServiceChange(String property, ChangeKind kind, @Nullable String oldValue, @Nullable String newValue) {
    }
}
