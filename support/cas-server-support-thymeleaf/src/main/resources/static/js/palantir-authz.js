async function initializeHeimdallOperations() {

    if (!CAS_FEATURES.includes("Authorization")) {
        hideElements("#heimdall");
        return;
    }

    const heimdallResourcesTable = $("#heimdallResourcesTable").DataTable({
        pageLength: 10,
        columnDefs: [
            {visible: false, targets: 0},
            {visible: false, targets: 1}
        ],
        autoWidth: false,
        drawCallback: settings => {
            $("#heimdallResourcesTable tr").addClass("mdc-data-table__row");
            $("#heimdallResourcesTable td").addClass("mdc-data-table__cell");

            const api = settings.api;
            const rows = api.rows({page: "current"}).nodes();
            let last = null;
            api.column(0, {page: "current"})
                .data()
                .each((group, i) => {
                    if (last !== group) {
                        $(rows).eq(i).before(
                            `<tr style='font-weight: bold; background-color:var(--cas-theme-primary); color:var(--mdc-text-button-label-text-color);'>
                                            <td colspan="3">Namespace: ${group}</td>
                                        </tr>`.trim());
                        last = group;
                    }
                });
        }
    });

    if (CasActuatorEndpoints.heimdall()) {
        const heimdallViewResourceEditor = initializeAceEditor("heimdallViewResourceEditor", "json");
        heimdallViewResourceEditor.setReadOnly(true);

        function viewHeimdallResource(namespace, resourceId) {
            $.get(`${CasActuatorEndpoints.heimdall()}/resources/${namespace}/${resourceId}`, response => {
                heimdallViewResourceEditor.setValue(JSON.stringify(response, null, 2));
                heimdallViewResourceEditor.gotoLine(1);

                const beautify = ace.require("ace/ext/beautify");
                beautify.beautify(heimdallViewResourceEditor.session);

                const dialog = window.mdc.dialog.MDCDialog.attachTo(document.getElementById("heimdallViewResourceDialog"));
                dialog["open"]();
            })
                .fail((xhr, status, error) => {
                    console.error("Error fetching data:", error);
                    displayBanner(xhr);
                });
        }

        initializeDataTableContextMenu({
            table: heimdallResourcesTable,
            selector: "#heimdallResourcesTable tbody tr",
            items: {
                view: {name: "View Resource", icon: contextMenuIcon("mdi-eye")}
            },
            callback: (key, context) => {
                if (key === "view") {
                    viewHeimdallResource(context.rowData.namespace, context.rowData.resourceId);
                }
            }
        });

        function fetchHeimdallResources() {
            $.get(`${CasActuatorEndpoints.heimdall()}/resources`, response => {
                heimdallResourcesTable.clear();
                for (const [key, value] of Object.entries(response)) {
                    for (const resource of Object.values(value)) {
                        heimdallResourcesTable.row.add({
                            0: `<code>${key}</code>`,
                            1: `${resource.id ?? "N/A"}`,
                            2: `<code>${resource.pattern ?? "N/A"}</code>`,
                            3: `<code>${resource.method ?? "N/A"}</code>`,
                            4: `<code>${resource.enforceAllPolicies ?? "false"}</code>`,
                            namespace: key,
                            resourceId: resource.id
                        });
                    }
                }
                heimdallResourcesTable.draw();
            }).fail((xhr, status, error) => {
                console.error("Error fetching data:", error);
                displayBanner(xhr);
            });
        }

        fetchHeimdallResources();

        setInterval(() => {
            if (currentActiveTab === Tabs.ACCESS_STRATEGY.index) {
                fetchHeimdallResources();
            }
        }, palantirSettings().refreshInterval);
    }

}

async function initializeAccessStrategyOperations() {

    if (!CAS_FEATURES.includes("SAMLIdentityProvider")) {
        hideElements("#accessEntityIdLabel");
    }
    if (!CAS_FEATURES.includes("OpenIDConnect") && !CAS_FEATURES.includes("OAuth")) {
        hideElements("#accessClientIdLabel");
    }

    const accessStrategyEditor = initializeAceEditor("accessStrategyEditor");
    accessStrategyEditor.setReadOnly(true);

    const accessStrategyAttributesTable = $("#accessStrategyAttributesTable").DataTable({
        pageLength: 10,
        drawCallback: settings => {
            $("#accessStrategyAttributesTable tr").addClass("mdc-data-table__row");
            $("#accessStrategyAttributesTable td").addClass("mdc-data-table__cell");
        }
    });

    $("button[name=accessStrategyButton]").off().on("click", () => {
        if (CasActuatorEndpoints.serviceAccess()) {
            hideBanner();
            accessStrategyAttributesTable.clear();

            const form = document.getElementById("fmAccessStrategy");
            if (!form.reportValidity()) {
                return false;
            }

            accessStrategyEditor.setValue("");
            const formData = $(form).serializeArray();
            const renamedData = formData.filter(item => item.value !== "").map(item => {
                const newName = $(`[name="${item.name}"]`).data("param-name") || item.name;
                return {name: newName, value: item.value};
            });

            $.ajax({
                url: CasActuatorEndpoints.serviceAccess(),
                type: "POST",
                contentType: "application/x-www-form-urlencoded",
                data: $.param(renamedData),
                success: (response, status, xhr) => {
                    showElements("#accessStrategyEditorContainer");
                    showElements("#accessStrategyAttributesContainer");

                    accessStrategyEditor.setValue(JSON.stringify(response.registeredService, null, 2));
                    accessStrategyEditor.gotoLine(1);

                    for (const [key, value] of Object.entries(response.authentication.principal.attributes)) {
                        accessStrategyAttributesTable.row.add({
                            0: `<code>${key}</code>`,
                            1: `<code>${value}</code>`
                        });
                    }
                    accessStrategyAttributesTable.draw();
                    updateNavigationSidebar();
                    $("#authorizedServiceNavigation").off().on("click", () => navigateToApplication(response.registeredService.id));
                },
                error: (xhr, status, error) => {
                    hideElements("#accessStrategyEditorContainer");
                    hideElements("#accessStrategyAttributesContainer");
                    displayBanner(`Status ${xhr.status}: Service is unauthorized.`);
                }
            });
        }
    });
}
