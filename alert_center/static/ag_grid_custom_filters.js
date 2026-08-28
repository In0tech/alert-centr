/* ------------------------------------------------------------------ */
/* Custom AG Grid filter components for dash-ag-grid.                 */
/* Registered on window.dashAgGridComponentFunctions — referenced    */
/* from columnDefs via {"filter": "<Name>"}.                          */
/*                                                                    */
/* DateRangeFilter: two <input type="datetime-local"> fields          */
/* ("From" / "To") that filter cell values whose underlying string    */
/* is in 'YYYY-MM-DD HH:MM:SS' format. Live filtering (no Apply       */
/* button). The sentinel '9999-12-31 23:59:59' (used for ongoing      */
/* alerts with no end_time) is treated as +infinity so it passes any   */
/* upper-bound ("To") filter, and never passes a lower-bound ("From") */
/* filter that is itself above any real date — which is the desired   */
/* behavior since an ongoing alert cannot be "before" a future date.  */
/* ------------------------------------------------------------------ */

(function () {
    if (typeof window === "undefined") return;

    var React = window.React;

    if (!window.dashAgGridComponentFunctions) {
        window.dashAgGridComponentFunctions = {};
    }

    // 'YYYY-MM-DD HH:MM:SS' or 'YYYY-MM-DDTHH:MM:SS' -> Date (local time).
    function parseCell(value) {
        if (value === null || value === undefined || value === "") return null;
        var s = String(value).replace(" ", "T");
        var d = new Date(s);
        return isNaN(d.getTime()) ? null : d;
    }

    // datetime-local input value ('YYYY-MM-DDTHH:MM') -> Date.
    function parseInput(value) {
        if (!value) return null;
        var d = new Date(value);
        return isNaN(d.getTime()) ? null : d;
    }

    // Date -> 'YYYY-MM-DDTHH:MM' for datetime-local inputs.
    function dateToInputValue(d) {
        if (!d) return "";
        var pad = function (n) { return n < 10 ? "0" + n : "" + n; };
        return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate())
             + "T" + pad(d.getHours()) + ":" + pad(d.getMinutes());
    }

    // Sentinel used by alert_interactive.py for ongoing alerts.
    var ONGOING_SENTINEL = "9999-12-31 23:59:59";

    var DateRangeFilter = React.forwardRef(function (props, ref) {
        var _React = window.React;
        var useState = _React.useState;
        var useImperativeHandle = _React.useImperativeHandle;
        var useEffect = _React.useEffect;

        var initial = (props && props.model) || {};
        var _a = useState(initial.from || ""),
            fromVal = _a[0], setFromVal = _a[1];
        var _b = useState(initial.to || ""),
            toVal = _b[0], setToVal = _b[1];

        // Keep local state in sync if grid restores model (e.g. via Reset).
        useEffect(function () {
            var m = (props && props.model) || {};
            setFromVal((m && m.from) || "");
            setToVal((m && m.to) || "");
        }, [props && props.model && (props.model.from + "|" + props.model.to)]);

        function fireChange(newFrom, newTo) {
            var model = null;
            if (newFrom || newTo) {
                model = { from: newFrom || null, to: newTo || null };
            }
            if (props && typeof props.onModelChange === "function") {
                props.onModelChange(model);
            }
        }

        function handleFromChange(e) {
            var v = e.target.value;
            setFromVal(v);
            fireChange(v, toVal);
        }

        function handleToChange(e) {
            var v = e.target.value;
            setToVal(v);
            fireChange(fromVal, v);
        }

        function handleReset() {
            setFromVal("");
            setToVal("");
            fireChange("", "");
        }

        useImperativeHandle(ref, function () {
            return {
                isFilterActive: function () {
                    return !!(fromVal || toVal);
                },
                doesFilterPass: function (params) {
                    var cellValue;
                    if (params && typeof params.getValue === "function") {
                        cellValue = params.getValue(params.node);
                    } else if (params && params.value !== undefined) {
                        cellValue = params.value;
                    } else {
                        return true;
                    }

                    // Ongoing alerts (sentinel) act as +infinity for upper bound.
                    if (cellValue === ONGOING_SENTINEL) {
                        var fromD = parseInput(fromVal);
                        // If a "From" filter is set and the sentinel is past it,
                        // the ongoing alert still passes (it is "after" the from).
                        // It also always passes any "To" filter (it is ongoing now).
                        return !fromD || true;
                    }

                    var cellD = parseCell(cellValue);
                    if (!cellD) return true;

                    if (fromVal) {
                        var fromD2 = parseInput(fromVal);
                        if (fromD2 && cellD < fromD2) return false;
                    }
                    if (toVal) {
                        var toD = parseInput(toVal);
                        if (toD && cellD > toD) return false;
                    }
                    return true;
                },
                getModel: function () {
                    if (!fromVal && !toVal) return null;
                    return { from: fromVal || null, to: toVal || null };
                },
                setModel: function (model) {
                    var m = model || {};
                    setFromVal(m.from || "");
                    setToVal(m.to || "");
                }
            };
        });

        var style = {
            padding: "8px",
            display: "flex",
            flexDirection: "column",
            gap: "6px",
            minWidth: "230px"
        };
        var rowStyle = { display: "flex", alignItems: "center", gap: "6px" };
        var labelStyle = { fontSize: "12px", minWidth: "32px", color: "#57606a" };
        var inputStyle = {
            padding: "3px 5px",
            border: "1px solid #d0d4da",
            borderRadius: "0px",
            fontSize: "12px",
            flex: "1 1 auto",
            minWidth: "0"
        };
        var btnStyle = {
            padding: "4px 8px",
            fontSize: "12px",
            cursor: "pointer",
            border: "1px solid #d0d4da",
            background: "#eceff3",
            color: "#1f2328",
            alignSelf: "flex-start"
        };

        return React.createElement(
            "div",
            { style: style },
            React.createElement(
                "div",
                { style: rowStyle },
                React.createElement("span", { style: labelStyle }, "From"),
                React.createElement("input", {
                    type: "datetime-local",
                    value: fromVal,
                    onChange: handleFromChange,
                    style: inputStyle
                })
            ),
            React.createElement(
                "div",
                { style: rowStyle },
                React.createElement("span", { style: labelStyle }, "To"),
                React.createElement("input", {
                    type: "datetime-local",
                    value: toVal,
                    onChange: handleToChange,
                    style: inputStyle
                })
            ),
            React.createElement("button", {
                type: "button",
                onClick: handleReset,
                style: btnStyle
            }, "Reset")
        );
    });

    window.dashAgGridComponentFunctions.DateRangeFilter = DateRangeFilter;
})();

