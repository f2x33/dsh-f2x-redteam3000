window.__ModuleLoader__.load({ id: "@dsh-f2x/redteam3000", factory: (require) => {
var module = { exports: {} }; var exports = module.exports;
"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name2 in all)
    __defProp(target, name2, { get: all[name2], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/client/index.ts
var index_exports = {};
__export(index_exports, {
  MANAGER_ROUTE: () => MANAGER_ROUTE,
  apply: () => apply,
  inject: () => inject,
  name: () => name
});
module.exports = __toCommonJS(index_exports);
var import_react = require("react");
var name = "@dsh-f2x/redteam3000-client";
var inject = ["slots"];
var MANAGER_ROUTE = "/f2x-manager";
var STYLES = `
.f2x-mgr { display: flex; flex-direction: column; gap: 18px; font-size: 13px; }
.f2x-mgr h3 { margin: 0 0 6px; font-size: 13px; text-transform: uppercase; letter-spacing: .08em; opacity: .6; }
.f2x-mgr ul { list-style: none; margin: 0; padding: 0; }
.f2x-mgr .row { display: flex; gap: 10px; padding: 5px 0; border-bottom: 1px solid color-mix(in srgb, currentColor 12%, transparent); }
.f2x-mgr .row b { min-width: 140px; font-weight: 600; }
.f2x-mgr .row span { opacity: .8; }
.f2x-mgr .card { border: 1px solid color-mix(in srgb, currentColor 18%, transparent); border-radius: 10px; padding: 12px; margin-bottom: 10px; }
.f2x-mgr code { font-size: 12px; }
.f2x-mgr .muted { opacity: .65; font-size: 12px; }
.f2x-mgr .warn { color: #c0392b; font-size: 12px; }
.f2x-mgr button { font: inherit; padding: 5px 12px; border-radius: 8px; border: 1px solid currentColor; background: transparent; cursor: pointer; }
.f2x-mgr pre { background: color-mix(in srgb, currentColor 7%, transparent); padding: 10px; border-radius: 8px; overflow: auto; max-height: 300px; font-size: 11px; }
`;
function createManagerView() {
  return function ManagerView() {
    const [snapshot, setSnapshot] = (0, import_react.useState)(void 0);
    const [busy, setBusy] = (0, import_react.useState)(void 0);
    const [output, setOutput] = (0, import_react.useState)(void 0);
    const [error, setError] = (0, import_react.useState)(void 0);
    const load = () => {
      void fetch(`${MANAGER_ROUTE}/state`, { headers: { accept: "application/json" } }).then((response) => response.ok ? response.json() : Promise.reject(new Error(String(response.status)))).then((value) => {
        setSnapshot(value);
        setError(void 0);
      }).catch((cause) => {
        setError(`\u8BFB\u53D6 ${MANAGER_ROUTE}/state \u5931\u8D25\uFF1A${String(cause?.message ?? cause)}`);
      });
    };
    (0, import_react.useEffect)(load, []);
    const post = (route, field, value) => {
      setBusy(value);
      setOutput(void 0);
      const body = new URLSearchParams();
      body.set(field, value);
      void fetch(`${MANAGER_ROUTE}${route}`, { method: "POST", body }).then((response) => response.text()).then((text) => {
        setOutput(text);
        load();
      }).catch((cause) => {
        setOutput(`\u8BF7\u6C42\u5931\u8D25\uFF1A${String(cause?.message ?? cause)}`);
      }).finally(() => {
        setBusy(void 0);
      });
    };
    const children = [];
    children.push((0, import_react.createElement)("h3", { key: "env" }, "\u73AF\u5883\u81EA\u68C0"));
    if (error !== void 0) children.push((0, import_react.createElement)("div", { key: "err", className: "warn" }, error));
    if (snapshot === void 0) {
      children.push((0, import_react.createElement)("div", { key: "loading", className: "muted" }, "\u8BFB\u53D6\u4E2D\u2026"));
    } else {
      if (snapshot.profile !== void 0) {
        children.push(
          (0, import_react.createElement)("div", { key: "profile", className: "muted" }, `profile: ${snapshot.profile}`)
        );
      }
      children.push(
        (0, import_react.createElement)(
          "ul",
          { key: "checks" },
          ...snapshot.checks.map(
            (line) => (0, import_react.createElement)(
              "li",
              { key: line.key, className: "row" },
              (0, import_react.createElement)("b", {}, `${line.ok ? "\u2705" : "\u274C"} ${line.label}`),
              (0, import_react.createElement)("span", {}, line.detail)
            )
          )
        )
      );
      children.push((0, import_react.createElement)("h3", { key: "rec-h" }, "\u63A8\u8350\u80FD\u529B"));
      children.push(
        (0, import_react.createElement)(
          "div",
          { key: "rec" },
          ...snapshot.recommended.map((entry) => {
            const report = snapshot.installed.find((item) => item.specifier === entry.specifier);
            const state = report === void 0 ? "\u672A\u5B89\u88C5" : report.installed ? "\u5DF2\u5B89\u88C5" : "\u672A\u627E\u5230";
            const parts = [
              (0, import_react.createElement)(
                "div",
                { key: "head", className: "row" },
                (0, import_react.createElement)("b", {}, entry.specifier),
                (0, import_react.createElement)("span", {}, state)
              ),
              (0, import_react.createElement)("div", { key: "why" }, entry.why),
              (0, import_react.createElement)("div", { key: "brings", className: "muted" }, entry.brings)
            ];
            for (const conflict of report?.conflicts ?? []) {
              parts.push(
                (0, import_react.createElement)(
                  "div",
                  { key: `c-${conflict.id}`, className: "warn" },
                  `\u26A0 loader id \u51B2\u7A81\uFF1A${conflict.id}\uFF08\u5DF2\u88AB ${conflict.owner} \u5360\u7528\uFF09`
                )
              );
            }
            for (const note of report?.notes ?? []) {
              parts.push((0, import_react.createElement)("div", { key: `n-${note}`, className: "muted" }, note));
            }
            parts.push(
              (0, import_react.createElement)(
                "button",
                {
                  key: "go",
                  disabled: busy === entry.specifier,
                  onClick: () => {
                    post("/install", "specifier", entry.specifier);
                  }
                },
                busy === entry.specifier ? "\u5B89\u88C5\u4E2D\u2026" : "\u5B89\u88C5 / \u91CD\u88C5"
              )
            );
            return (0, import_react.createElement)("div", { key: entry.specifier, className: "card" }, ...parts);
          })
        )
      );
      children.push((0, import_react.createElement)("h3", { key: "repo-h" }, "\u4ECE git \u4ED3\u5E93\u88C5\uFF08\u5B50\u5305\u5957\u4EF6\uFF09"));
      children.push(
        (0, import_react.createElement)(
          "div",
          { key: "repo" },
          ...snapshot.repos.map(
            (entry) => (0, import_react.createElement)(
              "div",
              { key: entry.url, className: "card" },
              (0, import_react.createElement)("code", {}, entry.url),
              (0, import_react.createElement)("div", { key: "why" }, entry.why),
              (0, import_react.createElement)("div", { key: "brings", className: "muted" }, entry.brings),
              (0, import_react.createElement)(
                "button",
                {
                  key: "go",
                  disabled: busy === entry.url,
                  onClick: () => {
                    post("/repo", "url", entry.url);
                  }
                },
                busy === entry.url ? "\u514B\u9686\u4E2D\u2026\uFF08\u5927\u4ED3\u5E93\u7EA6 1 \u5206\u949F\uFF09" : "\u514B\u9686\u5E76\u5217\u51FA\u53EF\u88C5\u9879"
              )
            )
          )
        )
      );
    }
    if (output !== void 0) {
      children.push((0, import_react.createElement)("h3", { key: "out-h" }, "\u8F93\u51FA"));
      children.push((0, import_react.createElement)("pre", { key: "out" }, output));
    }
    return (0, import_react.createElement)("div", { className: "f2x-mgr" }, ...children);
  };
}
function apply(ctx) {
  ctx.effect(() => {
    const style = document.createElement("style");
    style.textContent = STYLES;
    document.head.append(style);
    return () => {
      style.remove();
    };
  }, "f2x-manager: styles");
  ctx.slots.inject(
    "settings.section",
    () => ctx.slots.register(
      {
        name: "settings.section",
        id: "f2x-manager",
        order: 130,
        label: () => "f2x \u80FD\u529B\u7BA1\u7406\u5668"
      },
      createManagerView()
    )
  );
}
return module.exports; } });
