function createRegisteredServiceSaml2Fields() {
    createInputField({
        labelTitle: "Metadata Location",
        name: "registeredServiceMetadataLocation",
        paramName: "metadataLocation",
        required: true,
        containerId: "editServiceWizardSamlContainer",
        title: "Define the metadata location (URL, file path, etc) for the SAML2 service provider."
    });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Identity Provider Metadata Location",
        name: "registeredServiceIdPMetadataLocation",
        paramName: "idpMetadataLocation",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "Directory location of SAML2 identity provider metadata available to CAS as an override."
    });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Metadata Proxy Location",
        name: "registeredServiceMetadataProxyLocation",
        paramName: "metadataProxyLocation",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "Proxy endpoint (i.e. <code>https://proxy-address:8901</code>) to fetch service metadata from URL resources."
    });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Metadata Max Validity",
        name: "registeredServiceMetadataMaxValidity",
        paramName: "metadataMaxValidity",
        required: false,
        dataType: "number",
        containerId: "editServiceWizardSamlContainer",
        title: "Defines a filter that requires the presence of a <code>ValidUntil</code> attribute on the root element of the metadata document."
    });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Metadata Signature Location",
        name: "registeredServiceMetadataSignatureLocation",
        paramName: "metadataSignatureLocation",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "Location of the metadata signing certificate/public key to validate the metadata which must be defined from system files or classpath. If defined, will enforce the <code>SignatureValidationFilter</code> validation filter on metadata."
    });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Required Authentication Context Class",
        name: "registeredServiceRequiredAuthenticationContextClass",
        paramName: "requiredAuthenticationContextClass",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "If defined, will specify the SAML authentication context class in the final response."
    });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Required NameID Format",
        name: "registeredServiceRequiredNameIdFormat",
        paramName: "requiredNameIdFormat",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "If defined, will force the indicated Name ID format in the final SAML response. "
    });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "NameID Qualifier",
        name: "registeredServiceNameIdQualifier",
        paramName: "nameIdQualifier",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "Defines the NameID qualifier to be used in SAML responses."
    });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Service Provider NameID Qualifier",
        name: "registeredServiceSPNameIdQualifier",
        paramName: "serviceProviderNameIdQualifier",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "Defines the Service Provider NameID qualifier to be used in SAML responses."
    });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Issuer Entity ID",
        name: "registeredServiceIssuerEntityId",
        paramName: "issuerEntityId",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "If defined, will override the issuer value with the given identity provider entity id. This may be useful in cases where CAS needs to maintain multiple identity provider entity ids."
    });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Subject Locality",
        name: "registeredServiceSubjectLocality",
        paramName: "subjectLocality",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "If defined, will overwrite the <code>SubjectLocality</code> attribute of the SAML2 authentication statement."
    });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Logout Response Binding",
        name: "registeredServiceLogoutResponseBinding",
        paramName: "logoutResponseBinding",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "Defines the logout response binding to use when sending SAML logout responses to the service provider."
    });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Assertion Audience",
        name: "registeredServiceAssertionAudience",
        paramName: "assertionAudiences",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "Defines a comma-separated list of audience values to include in SAML assertions."
    });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Encryptable Attributes",
        name: "registeredServiceEncryptableAttributes",
        paramName: "encryptableAttributes",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "Defines a comma-separated list of attribute names that should be encrypted in SAML assertions."
    })
        .data("renderer", function (value) {
            return ["java.util.HashSet", value.split(",").filter(v => v != null && v !== "")];
        });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Skew Allowance",
        name: "registeredServiceSkewAllowance",
        paramName: "skewAllowance",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "If defined, indicates number of seconds used to skew authentication dates such as valid-from and valid-until elements, etc."
    });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Validity Until",
        name: "registeredServiceValidityUntil",
        paramName: "validityUntil",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "If defined, indicates the number of seconds from now used for the valid-until elements"
    });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Signing Signature Reference Digest Methods",
        name: "registeredServiceSigningSignatureReferenceDigestMethods",
        paramName: "signingSignatureReferenceDigestMethods",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "Defines a comma-separated list of digest methods to use when signing SAML messages."
    })
        .data("renderer", function (value) {
            return ["java.util.ArrayList", value.split(",").filter(v => v != null && v !== "")];
        });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Signing Signature Algorithms",
        name: "registeredServiceSigningSignatureAlgorithms",
        paramName: "signingSignatureAlgorithms",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "Defines a comma-separated list of signature algorithms to use when signing SAML messages."
    })
        .data("renderer", function (value) {
            return ["java.util.ArrayList", value.split(",").filter(v => v != null && v !== "")];
        });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Signing Signature Blacklisted Algorithms",
        name: "registeredServiceSigningSignatureBlackListedAlgorithms",
        paramName: "signingSignatureBlackListedAlgorithms",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "Defines a comma-separated list of blacklisted signature algorithms to avoid when signing SAML messages."
    })
        .data("renderer", function (value) {
            return ["java.util.ArrayList", value.split(",").filter(v => v != null && v !== "")];
        });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Signing Signature Whitelisted Algorithms",
        name: "registeredServiceSigningSignatureWhiteListedAlgorithms",
        paramName: "signingSignatureBlackListedAlgorithms",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "Defines a comma-separated list of whitelisted signature algorithms to avoid when signing SAML messages."
    })
        .data("renderer", function (value) {
            return ["java.util.ArrayList", value.split(",").filter(v => v != null && v !== "")];
        });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Whitelist/Blacklist Precedence",
        name: "registeredServiceWhiteListBlackListPrecedence",
        paramName: "whiteListBlackListPrecedence",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "Defines the precedence of whitelists/blacklists when selecting algorithms for signing/encryption. Accepted values are <code>INCLUDE</code> or <code>EXCLUDE</code>."
    })
        .css("text-transform", "uppercase")
        .on("input", function () {
            const value = $(this).val().toUpperCase();
            $(this).val(value);
        });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Encryption Data Algorithms",
        name: "registeredServiceEncryptionDataAlgorithms",
        paramName: "encryptionDataAlgorithms",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "Defines a comma-separated list of data encryption algorithms to use when encrypting SAML assertions."
    })
        .data("renderer", function (value) {
            return ["java.util.ArrayList", value.split(",").filter(v => v != null && v !== "")];
        });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Encryption Key Algorithms",
        name: "registeredServiceEncryptionKeyAlgorithms",
        paramName: "encryptionKeyAlgorithms",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "Defines a comma-separated list of key encryption algorithms to use when encrypting SAML assertions."
    })
        .data("renderer", function (value) {
            return ["java.util.ArrayList", value.split(",").filter(v => v != null && v !== "")];
        });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Encryption Blacklisted Algorithms",
        name: "registeredServiceEncryptionBlackListedAlgorithms",
        paramName: "encryptionBlackListedAlgorithms",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "Defines a comma-separated list of blacklisted algorithms to avoid when encrypting SAML assertions."
    })
        .data("renderer", function (value) {
            return ["java.util.ArrayList", value.split(",").filter(v => v != null && v !== "")];
        });
    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Encryption Whitelisted Algorithms",
        name: "registeredServiceEncryptionWhiteListedAlgorithms",
        paramName: "encryptionWhiteListedAlgorithms",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "Defines a comma-separated list of whitelisted algorithms to avoid when encrypting SAML assertions."
    })
        .data("renderer", function (value) {
            return ["java.util.ArrayList", value.split(",").filter(v => v != null && v !== "")];
        });


    createSelectField({
        containerId: "editServiceWizardSamlContainer",
        labelTitle: "Sign Assertions:",
        paramName: "signAssertions",
        options: [
            {value: "UNDEFINED", text: "UNDEFINED"},
            {value: "TRUE", text: "TRUE"},
            {value: "", text: "FALSE", selected: true}
        ],
        helpText: "Specify whether SAML assertions should be signed for this service provider."
    });

    createSelectField({
        containerId: "editServiceWizardSamlContainer",
        labelTitle: "Sign Responses:",
        paramName: "signResponses",
        options: [
            {value: "UNDEFINED", text: "UNDEFINED"},
            {value: "", text: "TRUE", selected: true},
            {value: "FALSE", text: "FALSE"}
        ],
        helpText: "Specify whether SAML assertions should be signed for this service provider."
    });

    createSelectField({
        cssClasses: "advanced-option",
        containerId: "editServiceWizardSamlContainer",
        labelTitle: "Sign Logout Responses:",
        paramName: "signLogoutResponse",
        options: [
            {value: "", text: "UNDEFINED", selected: true},
            {value: "TRUE", text: "TRUE"},
            {value: "FALSE", text: "FALSE"}
        ],
        helpText: "Specify whether SAML assertions should be signed for this service provider."
    });

    createSelectField({
        cssClasses: "advanced-option",
        containerId: "editServiceWizardSamlContainer",
        labelTitle: "Sign Logout Requests:",
        paramName: "signLogoutRequest",
        options: [
            {value: "", text: "UNDEFINED", selected: true},
            {value: "TRUE", text: "TRUE"},
            {value: "FALSE", text: "FALSE"}
        ],
        helpText: "Specify whether SAML assertions should be signed for this service provider."
    });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Metadata Criteria Direction",
        name: "registeredServiceMetadataCriteriaDirection",
        paramName: "metadataCriteriaDirection",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "Defines the metadata criteria direction (e.g. INCLUDE or EXCLUDE)."
    });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Metadata Criteria Pattern",
        name: "registeredServiceMetadataCriteriaPattern",
        paramName: "metadataCriteriaPattern",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "Defines the pattern used to filter metadata entities according to the criteria."
    });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Metadata Expiration Duration",
        name: "registeredServiceMetadataExpirationDuration",
        paramName: "metadataExpirationDuration",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "Defines how long metadata is considered valid (e.g., an ISO-8601 duration like PT60M)."
    });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Signing Credential Fingerprint",
        name: "registeredServiceSigningCredentialFingerprint",
        paramName: "signingCredentialFingerprint",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "Specifies the fingerprint of the signing credential used for SAML signing operations."
    });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Signing Key Algorithm",
        name: "registeredServiceSigningKeyAlgorithm",
        paramName: "signingKeyAlgorithm",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "Defines the algorithm used for signing keys"
    });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Metadata Criteria Roles",
        name: "registeredServiceMetadataCriteriaRoles",
        paramName: "metadataCriteriaRoles",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "Defines the metadata role(s) used when filtering entities (i.e. `SPSSODescriptor`, `IDPSSODescriptor`)."
    });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Signing Credential Type",
        name: "registeredServiceSigningCredentialType",
        paramName: "signingCredentialType",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "Specifies the type of signing credential used (e.g., X509, BASIC)."
    });

    createInputField({
        cssClasses: "advanced-option",
        labelTitle: "Signature Canonicalization Algorithm",
        name: "registeredServiceSigningSignatureCanonicalizationAlgorithm",
        paramName: "signingSignatureCanonicalizationAlgorithm",
        required: false,
        containerId: "editServiceWizardSamlContainer",
        title: "Defines which canonicalization algorithm is used for XML signature processing."
    });
}

function createRegisteredServiceMetadataCriteriaEntityAttribute() {
    createMappedInputField({
        containerId: "editServiceWizardSamlMetadataCriteriaEntityAttributesContainer",
        keyField: "metadataCriteriaEntityAttribute",
        keyLabel: "Entity Attribute",
        valueField: "metadataCriteriaEntityAttributeValue",
        valueLabel: "Entity attribute value(s) separated by comma (i.e. <code>http://refeds.org/category/research-and-scholarship</code>)",
        containerField: "metadataCriteriaEntityAttributes",
        multipleValues: true
    });
}

function createRegisteredServiceAttributeNameFormat() {
    createMappedInputField({
        containerId: "editServiceWizardSamlAttributeNameFormatsContainer",
        keyField: "attributeName-format",
        keyLabel: "Attribute Name",
        valueField: "attributeFormatValue",
        valueLabel: "Attribute Format (i.e. basic, uri, unspecified, etc)",
        containerField: "attributeNameFormats"
    });
}

function createRegisteredServiceAttributeValueTypes() {
    createMappedInputField({
        containerId: "editServiceWizardSamlAttributeValueTypesContainer",
        keyField: "attributeName-valueType",
        keyLabel: "Attribute Name",
        valueField: "attributeValueType",
        valueLabel: "Attribute Value Type (i.e. <code>XSString, XSURI, NameIDType</code>, etc)",
        containerField: "attributeValueTypes"
    });
}

function createRegisteredServiceAttributeFriendlyNames() {
    createMappedInputField({
        containerId: "editServiceWizardSamlAttributeFriendlyNamesContainer",
        keyField: "attributeName-friendly",
        keyLabel: "Attribute Name",
        valueField: "attributeFriendlyName",
        valueLabel: "Attribute Friendly Name",
        containerField: "attributeFriendlyNames"
    });
}

function createSamlRegisteredServiceAttributeReleasePolicy() {
    const $registeredServiceAttributeReleasePolicy = $("#registeredServiceAttributeReleasePolicy");

    const releasePolicyOptions = [
        {
            value: "org.apereo.cas.support.saml.services.InCommonRSAttributeReleasePolicy",
            text: "INCOMMON R&S",
            data: {
                markerClass: true,
                serviceClass: "SamlRegisteredService"
            }
        },
        {
            value: "org.apereo.cas.support.saml.services.RefedsRSAttributeReleasePolicy",
            text: "REFEDS R&S",
            data: {
                markerClass: true,
                serviceClass: "SamlRegisteredService"
            }
        },
        {
            value: "org.apereo.cas.support.saml.services.MetadataRequestedAttributesAttributeReleasePolicy",
            text: "METADATA REQUESTED ATTRIBUTES",
            data: {
                markerClass: true,
                serviceClass: "SamlRegisteredService"
            }
        },
        {
            value: "org.apereo.cas.support.saml.services.MetadataEntityAttributesAttributeReleasePolicy",
            text: "METADATA ENTITY ATTRIBUTES",
            data: {
                markerClass: true,
                serviceClass: "SamlRegisteredService"
            }
        },
        {
            value: "org.apereo.cas.support.saml.services.AuthnRequestRequestedAttributesAttributeReleasePolicy",
            text: "AUTHN REQUEST REQUESTED ATTRIBUTES",
            data: {
                markerClass: true,
                serviceClass: "SamlRegisteredService"
            }
        },
        {
            value: "org.apereo.cas.support.saml.services.AuthnRequestRequesterIdAttributeReleasePolicy",
            text: "AUTHN REQUEST REQUESTER ID",
            data: {
                markerClass: true,
                serviceClass: "SamlRegisteredService"
            }
        },
        {
            value: "org.apereo.cas.support.saml.services.MetadataRegistrationAuthorityAttributeReleasePolicy",
            text: "METADATA REGISTRATION AUTHORITY",
            data: {
                markerClass: true,
                serviceClass: "SamlRegisteredService"
            }
        },
        {
            value: "org.apereo.cas.support.saml.services.AnonymousAccessAttributeReleasePolicy",
            text: "ANONYMOUS ACCESS",
            data: {
                markerClass: true,
                serviceClass: "SamlRegisteredService"
            }
        },
        {
            value: "org.apereo.cas.support.saml.services.PseudonymousAccessAttributeReleasePolicy",
            text: "PSEUDONYMOUS ACCESS",
            data: {
                markerClass: true,
                serviceClass: "SamlRegisteredService"
            }
        },
        {
            value: "org.apereo.cas.support.saml.services.PersonalizedAccessAttributeReleasePolicy",
            text: "PERSONALIZED ACCESS",
            data: {
                markerClass: true,
                serviceClass: "SamlRegisteredService"
            }
        },
        {
            value: "org.apereo.cas.support.saml.services.MetadataEntityGroupAttributeReleasePolicy",
            text: "METADATA ENTITY GROUP",
            data: {
                markerClass: true,
                serviceClass: "SamlRegisteredService"
            }
        },
        {
            value: "org.apereo.cas.support.saml.services.PatternMatchingEntityIdAttributeReleasePolicy",
            text: "PATTERN MATCHING ENTITY IDS",
            data: {
                markerClass: true,
                serviceClass: "SamlRegisteredService"
            }
        },
        {
            value: "org.apereo.cas.support.saml.services.EduPersonTargetedIdAttributeReleasePolicy",
            text: "EDUPERSON TARGETED ID",
            data: {
                markerClass: true,
                serviceClass: "SamlRegisteredService"
            }
        },
        ...(
            PalantirDashboardConfiguration.scriptFactoryAvailable()
                ? [{
                    value: "org.apereo.cas.support.saml.services.GroovySamlRegisteredServiceAttributeReleasePolicy",
                    text: "GROOVY SAML"
                }]
                : []
        ),
    ];

    releasePolicyOptions.forEach(option => {
        if ($registeredServiceAttributeReleasePolicy.find(`option[value="${option.value}"]`).length === 0) {
            appendOptionsToDropDown({
                selectElement: $registeredServiceAttributeReleasePolicy,
                options: [option]
            });
        }
    });

    $registeredServiceAttributeReleasePolicy.selectmenu("refresh");



}

/**
 * Fill the SAML2 wizard from the metadata of a service provider. The metadata comes from a URL, read by the server
 * since browsers are not allowed to read most metadata URLs, or from XML the operator pastes or chooses. An aggregate
 * asks which of its service providers to use. What the metadata says is merged over what the wizard holds:
 * the entity id, the name, description, information and privacy URLs and logo the provider publishes, the metadata
 * location, its NameID format when it declares one, assertion signing when it wants assertions signed, an
 * attribute release policy for its research and scholarship category or the attributes it requests, and its
 * contacts. Nothing is saved.
 */
class PalantirSamlMetadataImport {
    static NAMESPACES = {
        md: "urn:oasis:names:tc:SAML:2.0:metadata",
        mdui: "urn:oasis:names:tc:SAML:metadata:ui",
        mdattr: "urn:oasis:names:tc:SAML:metadata:attribute",
        saml: "urn:oasis:names:tc:SAML:2.0:assertion",
        xml: "http://www.w3.org/XML/1998/namespace"
    };

    static ENTITY_CATEGORY = "http://macedir.org/entity-category";

    static CATEGORY_POLICIES = {
        "http://refeds.org/category/research-and-scholarship": "org.apereo.cas.support.saml.services.RefedsRSAttributeReleasePolicy",
        "http://id.incommon.org/category/research-and-scholarship": "org.apereo.cas.support.saml.services.InCommonRSAttributeReleasePolicy"
    };

    static REQUESTED_ATTRIBUTES_POLICY = "org.apereo.cas.support.saml.services.MetadataRequestedAttributesAttributeReleasePolicy";

    /**
     * Whether the server can read metadata from a URL for the wizard.
     *
     * @returns {boolean} true when the SAML2 metadata cache endpoint is available
     */
    static canReadUrls() {
        return Boolean(CasActuatorEndpoints.samlIdpRegisteredServiceMetadataCache());
    }

    /**
     * Ask for the metadata, read it and fill the wizard.
     *
     * @returns {Promise<void>} resolved once the wizard is filled or the operator gave up
     */
    static async open() {
        const location = String($("#registeredServiceMetadataLocation").val() ?? "").trim();
        const canReadUrls = PalantirSamlMetadataImport.canReadUrls();
        const result = await Swal.fire({
            title: "Fill from service provider metadata",
            html: `
                <form class="palantir-saml-metadata-import" onsubmit="return false;">
                    <label for="samlMetadataImportUrl">Metadata URL</label>
                    <input id="samlMetadataImportUrl" type="url" class="swal2-input" placeholder="https://sp.example.org/metadata"
                           value="${/^https?:\/\//i.test(location) ? escapePalantirMarkup(location) : ""}" ${canReadUrls ? "" : "disabled"}>
                    <p class="palantir-saml-metadata-import__hint">${canReadUrls
        ? "CAS reads the metadata at this URL, which also becomes the application's metadata location."
        : "Reading a URL needs the SAML2 metadata cache endpoint, which is not available; paste or choose the metadata instead."}</p>
                    <label for="samlMetadataImportXml">Or paste the metadata XML</label>
                    <textarea id="samlMetadataImportXml" class="swal2-textarea" rows="5" spellcheck="false"></textarea>
                    <label for="samlMetadataImportFile">Or choose a metadata file</label>
                    <label class="palantir-saml-metadata-import__file" for="samlMetadataImportFile">
                        <input id="samlMetadataImportFile" type="file" class="palantir-saml-metadata-import__file-input"
                               accept=".xml,application/xml,text/xml">
                        <i class="mdi mdi-file-upload-outline" aria-hidden="true"></i>
                        <span class="palantir-saml-metadata-import__file-text">
                            <strong id="samlMetadataImportFileName">Choose an XML file</strong>
                            <span id="samlMetadataImportFileHint">or drop it here</span>
                        </span>
                    </label>
                </form>`,
            width: Math.min(720, $(window).width() - 32),
            showCancelButton: true,
            confirmButtonText: "Read metadata",
            focusConfirm: false,
            didOpen: () => PalantirSamlMetadataImport.trackFileChoice(),
            preConfirm: () => {
                const url = String($("#samlMetadataImportUrl").val() ?? "").trim();
                const xml = String($("#samlMetadataImportXml").val() ?? "").trim();
                const file = $("#samlMetadataImportFile")[0]?.files?.[0] ?? null;
                if (!url && !xml && !file) {
                    Swal.showValidationMessage("Enter a metadata URL, or paste or choose the metadata XML.");
                    return false;
                }
                return {url: url, xml: xml, file: file};
            }
        });
        if (!result.isConfirmed) {
            return;
        }
        try {
            const source = await PalantirSamlMetadataImport.read(result.value);
            if (source) {
                await PalantirSamlMetadataImport.fill(source.entity, source.metadataLocation);
            }
        } catch (error) {
            Swal.fire({icon: "error", title: "The metadata could not be read", text: error.message});
        }
    }

    /**
     * Show the chosen file's name in the file drop zone, and mark the zone while a file is dragged over it.
     */
    static trackFileChoice() {
        const zone = $(".palantir-saml-metadata-import__file");
        $("#samlMetadataImportFile")
            .on("change", function () {
                const file = this.files?.[0];
                $("#samlMetadataImportFileName").text(file ? file.name : "Choose an XML file");
                $("#samlMetadataImportFileHint").text(file ? "Choose or drop another file to replace it" : "or drop it here");
                zone.toggleClass("has-file", Boolean(file)).removeClass("is-dragover");
            })
            .on("dragenter dragover", () => zone.addClass("is-dragover"))
            .on("dragleave drop", () => zone.removeClass("is-dragover"));
    }

    /**
     * Read the metadata and find the service provider to fill the wizard from.
     *
     * @param request the URL, pasted XML or chosen file
     * @returns {Promise<{entity: Element, metadataLocation: string|null}|null>} the provider's EntityDescriptor and
     * the metadata location to keep, or null when the operator chose none
     */
    static async read(request) {
        if (request.xml || request.file) {
            const text = request.xml || await request.file.text();
            const providers = PalantirSamlMetadataImport.serviceProviders(PalantirSamlMetadataImport.parse(text));
            if (providers.length === 0) {
                throw new Error("The metadata holds no SAML2 service provider.");
            }
            let entity = providers[0];
            if (providers.length > 1) {
                const chosen = await PalantirSamlMetadataImport.choose(providers.map(provider => provider.getAttribute("entityID")));
                entity = providers.find(provider => provider.getAttribute("entityID") === chosen);
            }
            return entity ? {entity: entity, metadataLocation: request.url || null} : null;
        }
        if (!PalantirSamlMetadataImport.canReadUrls()) {
            throw new Error("Reading metadata from a URL needs the SAML2 metadata cache endpoint. Paste or choose the metadata instead.");
        }
        let preview = await PalantirSamlMetadataImport.preview(request.url);
        if (!preview.metadata) {
            const chosen = await PalantirSamlMetadataImport.choose(preview.entities ?? []);
            if (!chosen) {
                return null;
            }
            preview = await PalantirSamlMetadataImport.preview(request.url, chosen);
        }
        const entity = PalantirSamlMetadataImport.serviceProviders(PalantirSamlMetadataImport.parse(preview.metadata))[0];
        if (!entity) {
            throw new Error("The metadata holds no SAML2 service provider.");
        }
        return {entity: entity, metadataLocation: preview.metadataLocation};
    }

    /**
     * Ask the server to read the metadata at a URL.
     *
     * @param url the metadata URL
     * @param entityId the service provider to read from an aggregate, if any
     * @returns {Promise<object>} the service providers the metadata holds and the metadata of the one read, if any
     */
    static async preview(url, entityId = null) {
        Swal.fire({
            title: "Reading metadata",
            text: url,
            allowOutsideClick: false,
            showConfirmButton: false,
            didOpen: () => Swal.showLoading()
        });
        try {
            return await $.ajax({
                url: `${CasActuatorEndpoints.samlIdpRegisteredServiceMetadataCache()}/preview`,
                method: "GET",
                data: entityId ? {metadataLocation: url, entityId: entityId} : {metadataLocation: url},
                dataType: "json",
                headers: {"Accept": "application/json"}
            });
        } catch (xhr) {
            throw new Error(xhr?.responseJSON?.error ?? `CAS could not read the metadata at ${url}.`, {cause: xhr});
        } finally {
            Swal.close();
        }
    }

    /**
     * Ask which service provider of an aggregate to use.
     *
     * @param entityIds the entity ids of the service providers
     * @returns {Promise<string|null>} the chosen entity id, or null
     */
    static async choose(entityIds) {
        const listId = "samlMetadataImportEntities";
        const result = await Swal.fire({
            title: "Choose the service provider",
            text: `The metadata holds ${entityIds.length} service providers.`,
            input: "text",
            inputLabel: "Entity ID",
            inputPlaceholder: "Start typing an entity id",
            showCancelButton: true,
            confirmButtonText: "Use this service provider",
            didOpen: () => {
                const datalist = $("<datalist>", {id: listId});
                entityIds.forEach(entityId => datalist.append($("<option>").attr("value", entityId)));
                $(Swal.getPopup()).append(datalist);
                $(Swal.getInput()).attr("list", listId);
            },
            inputValidator: value => entityIds.includes(String(value ?? "").trim())
                ? null
                : "Choose one of the entity ids the metadata holds."
        });
        return result.isConfirmed ? String(result.value).trim() : null;
    }

    /**
     * Parse metadata XML.
     *
     * @param text the XML
     * @returns {Document} the document
     */
    static parse(text) {
        const document = new DOMParser().parseFromString(text, "application/xml");
        if (document.getElementsByTagName("parsererror").length > 0) {
            throw new Error("This is not well-formed XML.");
        }
        return document;
    }

    /**
     * The entities of a metadata document that are SAML2 service providers.
     *
     * @param document the metadata document
     * @returns {Element[]} their EntityDescriptor elements
     */
    static serviceProviders(document) {
        const ns = PalantirSamlMetadataImport.NAMESPACES;
        return Array.from(document.getElementsByTagNameNS(ns.md, "EntityDescriptor"))
            .filter(entity => entity.getElementsByTagNameNS(ns.md, "SPSSODescriptor").length > 0);
    }

    /**
     * The text of the element in the operator's language, else in English, else the first one.
     *
     * @param elements the elements, one per language
     * @returns {string} the text, or an empty string
     */
    static localized(elements) {
        const ns = PalantirSamlMetadataImport.NAMESPACES;
        const languages = [String(navigator.language ?? "en").toLowerCase().split("-")[0], "en"];
        const language = element => String(element.getAttributeNS(ns.xml, "lang") || element.getAttribute("xml:lang") || "").toLowerCase();
        const chosen = languages.map(code => elements.find(element => language(element).split("-")[0] === code)).find(Boolean)
            ?? elements[0];
        return String(chosen?.textContent ?? "").trim();
    }

    /**
     * Whether a value is a web address the wizard may link to.
     *
     * @param value the value
     * @returns {boolean} true for an http or https URL
     */
    static isWebAddress(value) {
        return /^https?:\/\/\S+$/i.test(String(value ?? ""));
    }

    /**
     * Describe a service provider as the parts of an application definition its metadata settles.
     *
     * @param entity the provider's EntityDescriptor
     * @param metadataLocation the metadata location to keep, if any
     * @returns {{definition: object, filled: string[]}} the definition's parts and the names of the fields they fill
     */
    static describe(entity, metadataLocation) {
        const ns = PalantirSamlMetadataImport.NAMESPACES;
        const children = (parent, namespace, name) => Array.from(parent?.children ?? [])
            .filter(child => child.namespaceURI === namespace && child.localName === name);
        const provider = entity.getElementsByTagNameNS(ns.md, "SPSSODescriptor")[0];
        const uiInfo = provider.getElementsByTagNameNS(ns.mdui, "UIInfo")[0] ?? null;
        const ui = name => uiInfo ? Array.from(uiInfo.getElementsByTagNameNS(ns.mdui, name)) : [];
        const definition = {};
        const filled = [];
        const set = (field, label, value) => {
            if (value !== null && value !== undefined && value !== "") {
                definition[field] = value;
                filled.push(label);
            }
        };

        const entityId = entity.getAttribute("entityID");
        set("serviceId", "Entity ID", entityId);
        const organization = children(entity, ns.md, "Organization")[0];
        let host;
        try {
            host = new URL(entityId).hostname;
        } catch (error) {
            host = "";
        }
        set("name", "Name", PalantirSamlMetadataImport.localized(ui("DisplayName"))
            || PalantirSamlMetadataImport.localized(children(organization, ns.md, "OrganizationDisplayName"))
            || host || entityId);
        const description = PalantirSamlMetadataImport.localized(ui("Description"));
        set("description", "Description", description ? escapePalantirMarkup(description) : "");
        const informationUrl = PalantirSamlMetadataImport.localized(ui("InformationURL"));
        set("informationUrl", "Information URL", PalantirSamlMetadataImport.isWebAddress(informationUrl) ? informationUrl : "");
        const privacyUrl = PalantirSamlMetadataImport.localized(ui("PrivacyStatementURL"));
        set("privacyUrl", "Privacy URL", PalantirSamlMetadataImport.isWebAddress(privacyUrl) ? privacyUrl : "");
        const logo = ui("Logo")
            .filter(element => PalantirSamlMetadataImport.isWebAddress(element.textContent.trim()))
            .sort((first, second) => (Number(second.getAttribute("width")) || 0) * (Number(second.getAttribute("height")) || 0)
                - (Number(first.getAttribute("width")) || 0) * (Number(first.getAttribute("height")) || 0))[0];
        set("logo", "Logo", logo ? logo.textContent.trim() : "");
        set("metadataLocation", "Metadata Location", metadataLocation ?? "");

        const formats = children(provider, ns.md, "NameIDFormat").map(element => element.textContent.trim()).filter(Boolean);
        set("requiredNameIdFormat", "Required NameID Format", formats.length === 1 ? formats[0] : "");
        set("signAssertions", "Sign Assertions", provider.getAttribute("WantAssertionsSigned") === "true" ? "TRUE" : "");

        const categories = Array.from(entity.getElementsByTagNameNS(ns.mdattr, "EntityAttributes"))
            .flatMap(attributes => Array.from(attributes.getElementsByTagNameNS(ns.saml, "Attribute")))
            .filter(attribute => attribute.getAttribute("Name") === PalantirSamlMetadataImport.ENTITY_CATEGORY)
            .flatMap(attribute => Array.from(attribute.getElementsByTagNameNS(ns.saml, "AttributeValue")))
            .map(value => value.textContent.trim());
        const categoryPolicy = categories.map(category => PalantirSamlMetadataImport.CATEGORY_POLICIES[category]).find(Boolean);
        const requested = provider.getElementsByTagNameNS(ns.md, "RequestedAttribute").length > 0;
        const policy = categoryPolicy ?? (requested ? PalantirSamlMetadataImport.REQUESTED_ATTRIBUTES_POLICY : null);
        set("attributeReleasePolicy", "Attribute Release Policy", policy ? {"@class": policy} : null);

        const contacts = [...children(entity, ns.md, "ContactPerson"), ...children(provider, ns.md, "ContactPerson")]
            .slice(0, 3)
            .map(person => {
                const text = name => children(person, ns.md, name).map(element => element.textContent.trim()).find(Boolean) ?? "";
                const contact = {"@class": "org.apereo.cas.services.DefaultRegisteredServiceContact"};
                const name = [text("GivenName"), text("SurName")].filter(Boolean).join(" ");
                const details = {
                    name: name,
                    email: text("EmailAddress").replace(/^mailto:/i, ""),
                    phone: text("TelephoneNumber"),
                    department: text("Company"),
                    type: person.getAttribute("contactType") ?? ""
                };
                Object.entries(details).filter(([, value]) => value).forEach(([key, value]) => {
                    contact[key] = value;
                });
                return contact;
            })
            .filter(contact => Object.keys(contact).length > 1);
        set("contacts", "Contacts", contacts.length > 0 ? ["java.util.ArrayList", contacts] : null);
        return {definition: definition, filled: filled};
    }

    /**
     * Merge what the metadata settles over the definition the wizard holds, fill the wizard with the result and say
     * what was filled.
     *
     * @param entity the provider's EntityDescriptor
     * @param metadataLocation the metadata location to keep, if any
     * @returns {Promise<void>} resolved once the wizard is filled
     */
    static async fill(entity, metadataLocation) {
        const {definition, filled} = PalantirSamlMetadataImport.describe(entity, metadataLocation);
        let current;
        try {
            current = JSON.parse(ace.edit("wizardServiceEditor").getValue() || "{}");
        } catch (error) {
            current = {};
        }
        const merged = {...current, ...definition};
        merged["@class"] = current["@class"] ?? "org.apereo.cas.support.saml.services.SamlRegisteredService";
        populateWizardFromServiceDefinition(merged);
        for (let waited = 0; waited < 50 && (typeof isPopulatingWizard === "undefined" || isPopulatingWizard); waited++) {
            await new Promise(resolve => setTimeout(resolve, 100));
        }
        const location = merged.metadataLocation ? "" : " Enter where CAS should read its metadata from as the metadata location.";
        Swal.fire({
            icon: "success",
            title: "Filled from metadata",
            text: `${definition.serviceId}: ${filled.join(", ")}. Review the fields before saving.${location}`
        });
    }
}
