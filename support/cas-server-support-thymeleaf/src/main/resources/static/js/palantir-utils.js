function hideElements(elements) {
    $(elements)
        .css("display", "none")
        .addClass("hide")
        .addClass("d-none");
}

function showElements(elements) {
    $(elements)
        .css("display", "")
        .removeClass("hide")
        .removeClass("d-none");
}

function hideBanner() {
    notyf.dismissAll();
}

function closeAllDialogs() {
    $(".ui-dialog-content:visible").dialog("close");
}

function displayBanner(error) {
    let message = "";
    if (error.hasOwnProperty("status")) {
        switch (error.status) {
        case 401:
            message = "You are not authorized to access this resource. Are you sure you are authenticated?";
            break;
        case 403:
            message = "You are forbidden from accessing this resource. Are you sure you have the necessary permissions and the entry is correctly registered with CAS?";
            break;
        case 400:
        case 500:
        case 503:
            message = "Unable to process or accept the request. Check CAS server logs for details.";
            break;
        case 0:
            message = "Unable to contact the CAS server. Are you sure the server is reachable?";
            break;
        default:
            message = `HTTP error: ${error.status}. `;
            break;
        }
    }
    if (error.hasOwnProperty("path")) {
        message += `Unable to make an API call to ${error.path}. Is the endpoint enabled and available?`;
    }
    if (message.length === 0) {
        if (typeof error === "string") {
            message = error;
        } else {
            message = error.message;
        }
    }
    notyf.dismissAll();
    notyf.error(message);
}

function waitForActuator(endpoint, intervalMs = 2000) {
    return new Promise((resolve) => {
        function poll() {
            $.ajax({
                url: endpoint,
                method: "GET",
                dataType: "json",
                timeout: 3000
            })
                .done(function (data) {
                    resolve(data);
                })
                .fail(function () {
                    setTimeout(poll, intervalMs);
                });
        }

        poll();
    });
}

function highlightElements() {
    document
        .querySelectorAll("pre code[data-highlighted]")
        .forEach(el => delete el.dataset.highlighted);
    hljs.highlightAll();
}


function initializeTabs() {
    $(".jqueryui-tabs").tabs({
        activate: function () {
            const tabId = $(this).attr("id");
            if (tabId) {
                const active = $(this).tabs("option", "active");
                const storedTabs = localStorage.getItem("ActiveTabs");
                const activeTabs = storedTabs ? JSON.parse(storedTabs) : {};
                activeTabs[tabId] = active;
                localStorage.setItem("ActiveTabs", JSON.stringify(activeTabs));
            }
        }
    }).off().on("click", () => updateNavigationSidebar());
}

function initializeMenus() {
    $(".jqueryui-menu").menu();
}

function initializeDropDowns() {
    $(".jqueryui-selectmenu").selectmenu({
        width: "360px",
        change: function (event, ui) {
            const $select = $(this);
            const handlerNames = $select.data("change-handler").split(",");
            for (const handlerName of handlerNames) {
                if (handlerName && handlerName.length > 0 && typeof window[handlerName] === "function") {
                    const result = window[handlerName]($select, ui);
                    if (result !== undefined && result === false) {
                        break;
                    }
                }
            }
        }
    });
}

function initializeDatePickers() {
    $("input.jquery-datepicker").datepicker({
        showAnim: "slideDown",
        onSelect: function (date, ins) {
            $(ins).val(date);
            generateServiceDefinition();
            $(`#${$(ins).prop("id")}`).prev().find(".mdc-notched-outline__notch").hide();
        }
    });
}

function initializeTooltips() {
    $(function () {
        $(document).tooltip({
            items: "[title]:not(a)",
            show: {
                effect: "fade",
                delay: 800,
                duration: 500
            },
            hide: {
                effect: "fade",
                delay: 100
            },
            position: {
                my: "center bottom-20",
                at: "center top",
                using: function (position, feedback) {
                    $(this).css(position);
                    $("<div>")
                        .addClass("arrow")
                        .addClass(feedback.vertical)
                        .addClass(feedback.horizontal)
                        .appendTo(this);
                }
            }
        });
    });
}

function contextMenuIcon(icon) {
    return () => `context-menu-icon mdi ${icon}`;
}

const contextMenuActiveRowClass = "context-menu-active";

function contextMenuRow(options, context) {
    if (context?.$row?.length) {
        return context.$row;
    }
    if (options?.$trigger?.length) {
        return options.$trigger.closest("tr");
    }
    return $();
}

function highlightContextMenuRow(options, context) {
    $(`tr.${contextMenuActiveRowClass}`).removeClass(contextMenuActiveRowClass);
    const $row = contextMenuRow(options, context);
    if ($row.length) {
        $row.addClass(contextMenuActiveRowClass);
    }
}

function clearContextMenuRow(options, context) {
    const $row = contextMenuRow(options, context);
    if ($row.length) {
        $row.removeClass(contextMenuActiveRowClass);
    } else {
        $(`tr.${contextMenuActiveRowClass}`).removeClass(contextMenuActiveRowClass);
    }
}

function prepareContextMenuItems(items, context) {
    const sourceItems = typeof items === "function" ? items(context) : items;
    const menuItems = {};
    let separator = null;

    for (const [key, item] of Object.entries(sourceItems || {})) {
        if (typeof item === "string") {
            if (Object.keys(menuItems).length > 0) {
                separator = [key, item];
            }
            continue;
        }

        const visible = typeof item.visible === "function"
            ? item.visible(context)
            : item.visible !== false;
        if (!visible) {
            continue;
        }

        if (separator) {
            menuItems[separator[0]] = separator[1];
            separator = null;
        }

        const menuItem = {...item};
        delete menuItem.visible;
        menuItems[key] = menuItem;
    }
    return menuItems;
}

function initializeContextMenu({selector, callback, items, build, trigger = "right"}) {
    if (!jQuery.isFunction) {
        jQuery.isFunction = function (obj) {
            return typeof obj === "function";
        };
    }
    if (!jQuery.isWindow) {
        jQuery.isWindow = function (obj) {
            return obj != null && obj === obj.window;
        };
    }

    $.contextMenu("destroy", selector);

    const contextMenuOptions = {
        selector: selector,
        trigger: trigger,
        callback: function (key, options) {
            callback(key, options);
        },
        events: {
            show: function (options) {
                highlightContextMenuRow(options);
            },
            hide: function (options) {
                clearContextMenuRow(options);
            }
        },
        items: items
    };

    if (build) {
        delete contextMenuOptions.callback;
        delete contextMenuOptions.items;
        contextMenuOptions.build = function ($trigger, event) {
            const context = build($trigger, event);
            if (!context) {
                return false;
            }
            if (typeof context === "object") {
                context.$trigger ??= $trigger;
                context.$row ??= $trigger.closest("tr");
                context.event ??= event;
            }

            const menuItems = prepareContextMenuItems(items, context);
            if (Object.keys(menuItems).length === 0) {
                return false;
            }

            return {
                callback: function (key, options) {
                    options.context = context;
                    callback(key, options);
                },
                events: {
                    show: function (options) {
                        options.context = context;
                        highlightContextMenuRow(options, context);
                    },
                    hide: function (options) {
                        options.context = context;
                        clearContextMenuRow(options, context);
                    }
                },
                items: menuItems
            };
        };
    }

    $.contextMenu(contextMenuOptions);
}

function initializeDataTableContextMenu({table, selector, callback, items, trigger = "right"}) {
    initializeContextMenu({
        selector: selector,
        trigger: trigger,
        build: ($trigger, event) => {
            const $row = $trigger.closest("tr");
            if ($row.hasClass("dataTables_empty") || $row.hasClass("child") || $row.parent("thead").length > 0) {
                return false;
            }
            const row = table.row($row);
            const rowData = row.data();
            if (!rowData) {
                return false;
            }
            return {
                row: row,
                rowData: rowData,
                $row: $row,
                $trigger: $trigger,
                event: event
            };
        },
        items: items,
        callback: (key, options) => callback(key, options.context)
    });
}
