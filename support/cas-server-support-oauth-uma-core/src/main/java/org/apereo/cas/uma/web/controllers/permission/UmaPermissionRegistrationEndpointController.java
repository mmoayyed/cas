package org.apereo.cas.uma.web.controllers.permission;

import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.uma.UmaConfigurationContext;
import org.apereo.cas.uma.ticket.permission.UmaPermissionTicket;
import org.apereo.cas.uma.ticket.permission.UmaPermissionTicketFactory;
import org.apereo.cas.uma.web.controllers.BaseUmaEndpointController;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.util.LoggingUtils;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.hjson.JsonValue;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * This is {@link UmaPermissionRegistrationEndpointController}.
 *
 * @author Misagh Moayyed
 * @since 6.0.0
 */
@Slf4j
@Tag(name = "User Managed Access")
public class UmaPermissionRegistrationEndpointController extends BaseUmaEndpointController {
    public UmaPermissionRegistrationEndpointController(final UmaConfigurationContext umaConfigurationContext) {
        super(umaConfigurationContext);
    }

    /**
     * Gets permission ticket.
     *
     * @param body     the body
     * @param request  the request
     * @param response the response
     * @return the permission ticket
     */
    @PostMapping(value = OAuth20Constants.BASE_OAUTH20_URL + '/' + OAuth20Constants.UMA_PERMISSION_URL,
        consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
        summary = "Register permission ticket",
        description = "Registers a permission ticket and returns the ticket ID"
    )
    public ResponseEntity handle(
        @RequestBody
        final String body, final HttpServletRequest request,
        final HttpServletResponse response) {
        try {
            val profileResult = getAuthenticatedProfile(request, response, OAuth20Constants.UMA_PROTECTION_SCOPE);

            val umaRequest = MAPPER.readValue(JsonValue.readHjson(body).toString(), UmaPermissionRegistrationRequest.class);
            if (umaRequest == null || umaRequest.getResourceId() <= 0) {
                val model = buildResponseEntityErrorModel(HttpStatus.NOT_FOUND, "UMA request cannot be found or parsed");
                return new ResponseEntity(model, model, HttpStatus.BAD_REQUEST);
            }

            val resourceSetResult = getUmaConfigurationContext().getUmaResourceSetRepository().getById(umaRequest.getResourceId());
            if (resourceSetResult.isEmpty()) {
                val model = buildResponseEntityErrorModel(HttpStatus.NOT_FOUND, "Requested resource-set cannot be found");
                return new ResponseEntity(model, model, HttpStatus.BAD_REQUEST);
            }

            val resourceSet = resourceSetResult.get();
            if (!resourceSet.getOwner().equals(profileResult.getId())) {
                val model = buildResponseEntityErrorModel(HttpStatus.FORBIDDEN, "Resource-set owner does not match the authenticated profile");
                return new ResponseEntity(model, model, HttpStatus.BAD_REQUEST);
            }

            val umaTicketFactory = (UmaPermissionTicketFactory) getUmaConfigurationContext().getTicketFactory().get(UmaPermissionTicket.class);
            val permission = umaTicketFactory.create(resourceSet, umaRequest.getScopes(), umaRequest.getClaims());
            getUmaConfigurationContext().getTicketRegistry().addTicket(permission);
            val model = CollectionUtils.wrap("ticket", permission.getId(), "code", HttpStatus.CREATED);
            return new ResponseEntity(model, HttpStatus.OK);
        } catch (final Throwable e) {
            LoggingUtils.error(LOGGER, e);
        }
        return new ResponseEntity("Unable to complete the permission registration request.", HttpStatus.BAD_REQUEST);
    }
}
