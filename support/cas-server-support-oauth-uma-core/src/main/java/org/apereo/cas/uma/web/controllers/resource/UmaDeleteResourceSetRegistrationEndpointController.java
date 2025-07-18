package org.apereo.cas.uma.web.controllers.resource;

import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.uma.UmaConfigurationContext;
import org.apereo.cas.uma.ticket.resource.InvalidResourceSetException;
import org.apereo.cas.uma.web.controllers.BaseUmaEndpointController;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.util.LoggingUtils;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * This is {@link UmaDeleteResourceSetRegistrationEndpointController}.
 *
 * @author Misagh Moayyed
 * @since 6.0.0
 */
@Slf4j
@Tag(name = "User Managed Access")
public class UmaDeleteResourceSetRegistrationEndpointController extends BaseUmaEndpointController {
    public UmaDeleteResourceSetRegistrationEndpointController(final UmaConfigurationContext umaConfigurationContext) {
        super(umaConfigurationContext);
    }

    /**
     * Delete resource set response entity.
     *
     * @param id       the id
     * @param request  the request
     * @param response the response
     * @return the response entity
     */
    @DeleteMapping(OAuth20Constants.BASE_OAUTH20_URL + '/' + OAuth20Constants.UMA_RESOURCE_SET_REGISTRATION_URL + "/{id}")
    @Operation(summary = "Delete resource set", description = "Deletes the specified resource set",
        parameters = @Parameter(name = "id", required = true, in = ParameterIn.PATH, description = "Resource ID"))
    public ResponseEntity deleteResourceSet(@PathVariable("id") final long id, final HttpServletRequest request,
                                            final HttpServletResponse response) {
        try {
            val resourceSetResult = getUmaConfigurationContext().getUmaResourceSetRepository().getById(id);
            if (resourceSetResult.isEmpty()) {
                val model = buildResponseEntityErrorModel(HttpStatus.NOT_FOUND, "Requested resource-set cannot be found");
                return new ResponseEntity(model, model, HttpStatus.BAD_REQUEST);
            }
            val profileResult = getAuthenticatedProfile(request, response, OAuth20Constants.UMA_PROTECTION_SCOPE);
            val resourceSet = resourceSetResult.get();
            resourceSet.validate(profileResult);
            getUmaConfigurationContext().getUmaResourceSetRepository().remove(resourceSet);
            return new ResponseEntity(CollectionUtils.wrap("code", HttpStatus.NO_CONTENT, "resourceId", resourceSet.getId()), HttpStatus.OK);
        } catch (final InvalidResourceSetException e) {
            return new ResponseEntity(buildResponseEntityErrorModel(e), HttpStatus.BAD_REQUEST);
        } catch (final Exception e) {
            LoggingUtils.error(LOGGER, e);
        }
        return new ResponseEntity("Unable to complete the delete request.", HttpStatus.BAD_REQUEST);
    }
}
