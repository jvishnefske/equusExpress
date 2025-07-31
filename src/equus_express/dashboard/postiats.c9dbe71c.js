// modules are defined as an array
// [ module function, map of requires ]
//
// map of requires is short require name -> numeric require
//
// anything defined in a previous bundle is accessed via the
// orig method which is the require for previous bundles

(function (
  modules,
  entry,
  mainEntry,
  parcelRequireName,
  externals,
  distDir,
  publicUrl,
  devServer
) {
  /* eslint-disable no-undef */
  var globalObject =
    typeof globalThis !== 'undefined'
      ? globalThis
      : typeof self !== 'undefined'
      ? self
      : typeof window !== 'undefined'
      ? window
      : typeof global !== 'undefined'
      ? global
      : {};
  /* eslint-enable no-undef */

  // Save the require from previous bundle to this closure if any
  var previousRequire =
    typeof globalObject[parcelRequireName] === 'function' &&
    globalObject[parcelRequireName];

  var importMap = previousRequire.i || {};
  var cache = previousRequire.cache || {};
  // Do not use `require` to prevent Webpack from trying to bundle this call
  var nodeRequire =
    typeof module !== 'undefined' &&
    typeof module.require === 'function' &&
    module.require.bind(module);

  function newRequire(name, jumped) {
    if (!cache[name]) {
      if (!modules[name]) {
        if (externals[name]) {
          return externals[name];
        }
        // if we cannot find the module within our internal map or
        // cache jump to the current global require ie. the last bundle
        // that was added to the page.
        var currentRequire =
          typeof globalObject[parcelRequireName] === 'function' &&
          globalObject[parcelRequireName];
        if (!jumped && currentRequire) {
          return currentRequire(name, true);
        }

        // If there are other bundles on this page the require from the
        // previous one is saved to 'previousRequire'. Repeat this as
        // many times as there are bundles until the module is found or
        // we exhaust the require chain.
        if (previousRequire) {
          return previousRequire(name, true);
        }

        // Try the node require function if it exists.
        if (nodeRequire && typeof name === 'string') {
          return nodeRequire(name);
        }

        var err = new Error("Cannot find module '" + name + "'");
        err.code = 'MODULE_NOT_FOUND';
        throw err;
      }

      localRequire.resolve = resolve;
      localRequire.cache = {};

      var module = (cache[name] = new newRequire.Module(name));

      modules[name][0].call(
        module.exports,
        localRequire,
        module,
        module.exports,
        globalObject
      );
    }

    return cache[name].exports;

    function localRequire(x) {
      var res = localRequire.resolve(x);
      return res === false ? {} : newRequire(res);
    }

    function resolve(x) {
      var id = modules[name][1][x];
      return id != null ? id : x;
    }
  }

  function Module(moduleName) {
    this.id = moduleName;
    this.bundle = newRequire;
    this.require = nodeRequire;
    this.exports = {};
  }

  newRequire.isParcelRequire = true;
  newRequire.Module = Module;
  newRequire.modules = modules;
  newRequire.cache = cache;
  newRequire.parent = previousRequire;
  newRequire.distDir = distDir;
  newRequire.publicUrl = publicUrl;
  newRequire.devServer = devServer;
  newRequire.i = importMap;
  newRequire.register = function (id, exports) {
    modules[id] = [
      function (require, module) {
        module.exports = exports;
      },
      {},
    ];
  };

  // Only insert newRequire.load when it is actually used.
  // The code in this file is linted against ES5, so dynamic import is not allowed.
  // INSERT_LOAD_HERE

  Object.defineProperty(newRequire, 'root', {
    get: function () {
      return globalObject[parcelRequireName];
    },
  });

  globalObject[parcelRequireName] = newRequire;

  for (var i = 0; i < entry.length; i++) {
    newRequire(entry[i]);
  }

  if (mainEntry) {
    // Expose entry point to Node, AMD or browser globals
    // Based on https://github.com/ForbesLindesay/umd/blob/master/template.js
    var mainExports = newRequire(mainEntry);

    // CommonJS
    if (typeof exports === 'object' && typeof module !== 'undefined') {
      module.exports = mainExports;

      // RequireJS
    } else if (typeof define === 'function' && define.amd) {
      define(function () {
        return mainExports;
      });
    }
  }
})({"gigho":[function(require,module,exports,__globalThis) {
var global = arguments[3];
var HMR_HOST = null;
var HMR_PORT = null;
var HMR_SERVER_PORT = 1234;
var HMR_SECURE = false;
var HMR_ENV_HASH = "439701173a9199ea";
var HMR_USE_SSE = false;
module.bundle.HMR_BUNDLE_ID = "55f34c56c9dbe71c";
"use strict";
/* global HMR_HOST, HMR_PORT, HMR_SERVER_PORT, HMR_ENV_HASH, HMR_SECURE, HMR_USE_SSE, chrome, browser, __parcel__import__, __parcel__importScripts__, ServiceWorkerGlobalScope */ /*::
import type {
  HMRAsset,
  HMRMessage,
} from '@parcel/reporter-dev-server/src/HMRServer.js';
interface ParcelRequire {
  (string): mixed;
  cache: {|[string]: ParcelModule|};
  hotData: {|[string]: mixed|};
  Module: any;
  parent: ?ParcelRequire;
  isParcelRequire: true;
  modules: {|[string]: [Function, {|[string]: string|}]|};
  HMR_BUNDLE_ID: string;
  root: ParcelRequire;
}
interface ParcelModule {
  hot: {|
    data: mixed,
    accept(cb: (Function) => void): void,
    dispose(cb: (mixed) => void): void,
    // accept(deps: Array<string> | string, cb: (Function) => void): void,
    // decline(): void,
    _acceptCallbacks: Array<(Function) => void>,
    _disposeCallbacks: Array<(mixed) => void>,
  |};
}
interface ExtensionContext {
  runtime: {|
    reload(): void,
    getURL(url: string): string;
    getManifest(): {manifest_version: number, ...};
  |};
}
declare var module: {bundle: ParcelRequire, ...};
declare var HMR_HOST: string;
declare var HMR_PORT: string;
declare var HMR_SERVER_PORT: string;
declare var HMR_ENV_HASH: string;
declare var HMR_SECURE: boolean;
declare var HMR_USE_SSE: boolean;
declare var chrome: ExtensionContext;
declare var browser: ExtensionContext;
declare var __parcel__import__: (string) => Promise<void>;
declare var __parcel__importScripts__: (string) => Promise<void>;
declare var globalThis: typeof self;
declare var ServiceWorkerGlobalScope: Object;
*/ var OVERLAY_ID = '__parcel__error__overlay__';
var OldModule = module.bundle.Module;
function Module(moduleName) {
    OldModule.call(this, moduleName);
    this.hot = {
        data: module.bundle.hotData[moduleName],
        _acceptCallbacks: [],
        _disposeCallbacks: [],
        accept: function(fn) {
            this._acceptCallbacks.push(fn || function() {});
        },
        dispose: function(fn) {
            this._disposeCallbacks.push(fn);
        }
    };
    module.bundle.hotData[moduleName] = undefined;
}
module.bundle.Module = Module;
module.bundle.hotData = {};
var checkedAssets /*: {|[string]: boolean|} */ , disposedAssets /*: {|[string]: boolean|} */ , assetsToDispose /*: Array<[ParcelRequire, string]> */ , assetsToAccept /*: Array<[ParcelRequire, string]> */ , bundleNotFound = false;
function getHostname() {
    return HMR_HOST || (typeof location !== 'undefined' && location.protocol.indexOf('http') === 0 ? location.hostname : 'localhost');
}
function getPort() {
    return HMR_PORT || (typeof location !== 'undefined' ? location.port : HMR_SERVER_PORT);
}
// eslint-disable-next-line no-redeclare
let WebSocket = globalThis.WebSocket;
if (!WebSocket && typeof module.bundle.root === 'function') try {
    // eslint-disable-next-line no-global-assign
    WebSocket = module.bundle.root('ws');
} catch  {
// ignore.
}
var hostname = getHostname();
var port = getPort();
var protocol = HMR_SECURE || typeof location !== 'undefined' && location.protocol === 'https:' && ![
    'localhost',
    '127.0.0.1',
    '0.0.0.0'
].includes(hostname) ? 'wss' : 'ws';
// eslint-disable-next-line no-redeclare
var parent = module.bundle.parent;
if (!parent || !parent.isParcelRequire) {
    // Web extension context
    var extCtx = typeof browser === 'undefined' ? typeof chrome === 'undefined' ? null : chrome : browser;
    // Safari doesn't support sourceURL in error stacks.
    // eval may also be disabled via CSP, so do a quick check.
    var supportsSourceURL = false;
    try {
        (0, eval)('throw new Error("test"); //# sourceURL=test.js');
    } catch (err) {
        supportsSourceURL = err.stack.includes('test.js');
    }
    var ws;
    if (HMR_USE_SSE) ws = new EventSource('/__parcel_hmr');
    else try {
        // If we're running in the dev server's node runner, listen for messages on the parent port.
        let { workerData, parentPort } = module.bundle.root('node:worker_threads') /*: any*/ ;
        if (workerData !== null && workerData !== void 0 && workerData.__parcel) {
            parentPort.on('message', async (message)=>{
                try {
                    await handleMessage(message);
                    parentPort.postMessage('updated');
                } catch  {
                    parentPort.postMessage('restart');
                }
            });
            // After the bundle has finished running, notify the dev server that the HMR update is complete.
            queueMicrotask(()=>parentPort.postMessage('ready'));
        }
    } catch  {
        if (typeof WebSocket !== 'undefined') try {
            ws = new WebSocket(protocol + '://' + hostname + (port ? ':' + port : '') + '/');
        } catch (err) {
            // Ignore cloudflare workers error.
            if (err.message && !err.message.includes('Disallowed operation called within global scope')) console.error(err.message);
        }
    }
    if (ws) {
        // $FlowFixMe
        ws.onmessage = async function(event /*: {data: string, ...} */ ) {
            var data /*: HMRMessage */  = JSON.parse(event.data);
            await handleMessage(data);
        };
        if (ws instanceof WebSocket) {
            ws.onerror = function(e) {
                if (e.message) console.error(e.message);
            };
            ws.onclose = function() {
                console.warn("[parcel] \uD83D\uDEA8 Connection to the HMR server was lost");
            };
        }
    }
}
async function handleMessage(data /*: HMRMessage */ ) {
    checkedAssets = {} /*: {|[string]: boolean|} */ ;
    disposedAssets = {} /*: {|[string]: boolean|} */ ;
    assetsToAccept = [];
    assetsToDispose = [];
    bundleNotFound = false;
    if (data.type === 'reload') fullReload();
    else if (data.type === 'update') {
        // Remove error overlay if there is one
        if (typeof document !== 'undefined') removeErrorOverlay();
        let assets = data.assets;
        // Handle HMR Update
        let handled = assets.every((asset)=>{
            return asset.type === 'css' || asset.type === 'js' && hmrAcceptCheck(module.bundle.root, asset.id, asset.depsByBundle);
        });
        // Dispatch a custom event in case a bundle was not found. This might mean
        // an asset on the server changed and we should reload the page. This event
        // gives the client an opportunity to refresh without losing state
        // (e.g. via React Server Components). If e.preventDefault() is not called,
        // we will trigger a full page reload.
        if (handled && bundleNotFound && assets.some((a)=>a.envHash !== HMR_ENV_HASH) && typeof window !== 'undefined' && typeof CustomEvent !== 'undefined') handled = !window.dispatchEvent(new CustomEvent('parcelhmrreload', {
            cancelable: true
        }));
        if (handled) {
            console.clear();
            // Dispatch custom event so other runtimes (e.g React Refresh) are aware.
            if (typeof window !== 'undefined' && typeof CustomEvent !== 'undefined') window.dispatchEvent(new CustomEvent('parcelhmraccept'));
            await hmrApplyUpdates(assets);
            hmrDisposeQueue();
            // Run accept callbacks. This will also re-execute other disposed assets in topological order.
            let processedAssets = {};
            for(let i = 0; i < assetsToAccept.length; i++){
                let id = assetsToAccept[i][1];
                if (!processedAssets[id]) {
                    hmrAccept(assetsToAccept[i][0], id);
                    processedAssets[id] = true;
                }
            }
        } else fullReload();
    }
    if (data.type === 'error') {
        // Log parcel errors to console
        for (let ansiDiagnostic of data.diagnostics.ansi){
            let stack = ansiDiagnostic.codeframe ? ansiDiagnostic.codeframe : ansiDiagnostic.stack;
            console.error("\uD83D\uDEA8 [parcel]: " + ansiDiagnostic.message + '\n' + stack + '\n\n' + ansiDiagnostic.hints.join('\n'));
        }
        if (typeof document !== 'undefined') {
            // Render the fancy html overlay
            removeErrorOverlay();
            var overlay = createErrorOverlay(data.diagnostics.html);
            // $FlowFixMe
            document.body.appendChild(overlay);
        }
    }
}
function removeErrorOverlay() {
    var overlay = document.getElementById(OVERLAY_ID);
    if (overlay) {
        overlay.remove();
        console.log("[parcel] \u2728 Error resolved");
    }
}
function createErrorOverlay(diagnostics) {
    var overlay = document.createElement('div');
    overlay.id = OVERLAY_ID;
    let errorHTML = '<div style="background: black; opacity: 0.85; font-size: 16px; color: white; position: fixed; height: 100%; width: 100%; top: 0px; left: 0px; padding: 30px; font-family: Menlo, Consolas, monospace; z-index: 9999;">';
    for (let diagnostic of diagnostics){
        let stack = diagnostic.frames.length ? diagnostic.frames.reduce((p, frame)=>{
            return `${p}
<a href="${protocol === 'wss' ? 'https' : 'http'}://${hostname}:${port}/__parcel_launch_editor?file=${encodeURIComponent(frame.location)}" style="text-decoration: underline; color: #888" onclick="fetch(this.href); return false">${frame.location}</a>
${frame.code}`;
        }, '') : diagnostic.stack;
        errorHTML += `
      <div>
        <div style="font-size: 18px; font-weight: bold; margin-top: 20px;">
          \u{1F6A8} ${diagnostic.message}
        </div>
        <pre>${stack}</pre>
        <div>
          ${diagnostic.hints.map((hint)=>"<div>\uD83D\uDCA1 " + hint + '</div>').join('')}
        </div>
        ${diagnostic.documentation ? `<div>\u{1F4DD} <a style="color: violet" href="${diagnostic.documentation}" target="_blank">Learn more</a></div>` : ''}
      </div>
    `;
    }
    errorHTML += '</div>';
    overlay.innerHTML = errorHTML;
    return overlay;
}
function fullReload() {
    if (typeof location !== 'undefined' && 'reload' in location) location.reload();
    else if (typeof extCtx !== 'undefined' && extCtx && extCtx.runtime && extCtx.runtime.reload) extCtx.runtime.reload();
    else try {
        let { workerData, parentPort } = module.bundle.root('node:worker_threads') /*: any*/ ;
        if (workerData !== null && workerData !== void 0 && workerData.__parcel) parentPort.postMessage('restart');
    } catch (err) {
        console.error("[parcel] \u26A0\uFE0F An HMR update was not accepted. Please restart the process.");
    }
}
function getParents(bundle, id) /*: Array<[ParcelRequire, string]> */ {
    var modules = bundle.modules;
    if (!modules) return [];
    var parents = [];
    var k, d, dep;
    for(k in modules)for(d in modules[k][1]){
        dep = modules[k][1][d];
        if (dep === id || Array.isArray(dep) && dep[dep.length - 1] === id) parents.push([
            bundle,
            k
        ]);
    }
    if (bundle.parent) parents = parents.concat(getParents(bundle.parent, id));
    return parents;
}
function updateLink(link) {
    var href = link.getAttribute('href');
    if (!href) return;
    var newLink = link.cloneNode();
    newLink.onload = function() {
        if (link.parentNode !== null) // $FlowFixMe
        link.parentNode.removeChild(link);
    };
    newLink.setAttribute('href', // $FlowFixMe
    href.split('?')[0] + '?' + Date.now());
    // $FlowFixMe
    link.parentNode.insertBefore(newLink, link.nextSibling);
}
var cssTimeout = null;
function reloadCSS() {
    if (cssTimeout || typeof document === 'undefined') return;
    cssTimeout = setTimeout(function() {
        var links = document.querySelectorAll('link[rel="stylesheet"]');
        for(var i = 0; i < links.length; i++){
            // $FlowFixMe[incompatible-type]
            var href /*: string */  = links[i].getAttribute('href');
            var hostname = getHostname();
            var servedFromHMRServer = hostname === 'localhost' ? new RegExp('^(https?:\\/\\/(0.0.0.0|127.0.0.1)|localhost):' + getPort()).test(href) : href.indexOf(hostname + ':' + getPort());
            var absolute = /^https?:\/\//i.test(href) && href.indexOf(location.origin) !== 0 && !servedFromHMRServer;
            if (!absolute) updateLink(links[i]);
        }
        cssTimeout = null;
    }, 50);
}
function hmrDownload(asset) {
    if (asset.type === 'js') {
        if (typeof document !== 'undefined') {
            let script = document.createElement('script');
            script.src = asset.url + '?t=' + Date.now();
            if (asset.outputFormat === 'esmodule') script.type = 'module';
            return new Promise((resolve, reject)=>{
                var _document$head;
                script.onload = ()=>resolve(script);
                script.onerror = reject;
                (_document$head = document.head) === null || _document$head === void 0 || _document$head.appendChild(script);
            });
        } else if (typeof importScripts === 'function') {
            // Worker scripts
            if (asset.outputFormat === 'esmodule') return import(asset.url + '?t=' + Date.now());
            else return new Promise((resolve, reject)=>{
                try {
                    importScripts(asset.url + '?t=' + Date.now());
                    resolve();
                } catch (err) {
                    reject(err);
                }
            });
        }
    }
}
async function hmrApplyUpdates(assets) {
    global.parcelHotUpdate = Object.create(null);
    let scriptsToRemove;
    try {
        // If sourceURL comments aren't supported in eval, we need to load
        // the update from the dev server over HTTP so that stack traces
        // are correct in errors/logs. This is much slower than eval, so
        // we only do it if needed (currently just Safari).
        // https://bugs.webkit.org/show_bug.cgi?id=137297
        // This path is also taken if a CSP disallows eval.
        if (!supportsSourceURL) {
            let promises = assets.map((asset)=>{
                var _hmrDownload;
                return (_hmrDownload = hmrDownload(asset)) === null || _hmrDownload === void 0 ? void 0 : _hmrDownload.catch((err)=>{
                    // Web extension fix
                    if (extCtx && extCtx.runtime && extCtx.runtime.getManifest().manifest_version == 3 && typeof ServiceWorkerGlobalScope != 'undefined' && global instanceof ServiceWorkerGlobalScope) {
                        extCtx.runtime.reload();
                        return;
                    }
                    throw err;
                });
            });
            scriptsToRemove = await Promise.all(promises);
        }
        assets.forEach(function(asset) {
            hmrApply(module.bundle.root, asset);
        });
    } finally{
        delete global.parcelHotUpdate;
        if (scriptsToRemove) scriptsToRemove.forEach((script)=>{
            if (script) {
                var _document$head2;
                (_document$head2 = document.head) === null || _document$head2 === void 0 || _document$head2.removeChild(script);
            }
        });
    }
}
function hmrApply(bundle /*: ParcelRequire */ , asset /*:  HMRAsset */ ) {
    var modules = bundle.modules;
    if (!modules) return;
    if (asset.type === 'css') reloadCSS();
    else if (asset.type === 'js') {
        let deps = asset.depsByBundle[bundle.HMR_BUNDLE_ID];
        if (deps) {
            if (modules[asset.id]) {
                // Remove dependencies that are removed and will become orphaned.
                // This is necessary so that if the asset is added back again, the cache is gone, and we prevent a full page reload.
                let oldDeps = modules[asset.id][1];
                for(let dep in oldDeps)if (!deps[dep] || deps[dep] !== oldDeps[dep]) {
                    let id = oldDeps[dep];
                    let parents = getParents(module.bundle.root, id);
                    if (parents.length === 1) hmrDelete(module.bundle.root, id);
                }
            }
            if (supportsSourceURL) // Global eval. We would use `new Function` here but browser
            // support for source maps is better with eval.
            (0, eval)(asset.output);
            // $FlowFixMe
            let fn = global.parcelHotUpdate[asset.id];
            modules[asset.id] = [
                fn,
                deps
            ];
        }
        // Always traverse to the parent bundle, even if we already replaced the asset in this bundle.
        // This is required in case modules are duplicated. We need to ensure all instances have the updated code.
        if (bundle.parent) hmrApply(bundle.parent, asset);
    }
}
function hmrDelete(bundle, id) {
    let modules = bundle.modules;
    if (!modules) return;
    if (modules[id]) {
        // Collect dependencies that will become orphaned when this module is deleted.
        let deps = modules[id][1];
        let orphans = [];
        for(let dep in deps){
            let parents = getParents(module.bundle.root, deps[dep]);
            if (parents.length === 1) orphans.push(deps[dep]);
        }
        // Delete the module. This must be done before deleting dependencies in case of circular dependencies.
        delete modules[id];
        delete bundle.cache[id];
        // Now delete the orphans.
        orphans.forEach((id)=>{
            hmrDelete(module.bundle.root, id);
        });
    } else if (bundle.parent) hmrDelete(bundle.parent, id);
}
function hmrAcceptCheck(bundle /*: ParcelRequire */ , id /*: string */ , depsByBundle /*: ?{ [string]: { [string]: string } }*/ ) {
    checkedAssets = {};
    if (hmrAcceptCheckOne(bundle, id, depsByBundle)) return true;
    // Traverse parents breadth first. All possible ancestries must accept the HMR update, or we'll reload.
    let parents = getParents(module.bundle.root, id);
    let accepted = false;
    while(parents.length > 0){
        let v = parents.shift();
        let a = hmrAcceptCheckOne(v[0], v[1], null);
        if (a) // If this parent accepts, stop traversing upward, but still consider siblings.
        accepted = true;
        else if (a !== null) {
            // Otherwise, queue the parents in the next level upward.
            let p = getParents(module.bundle.root, v[1]);
            if (p.length === 0) {
                // If there are no parents, then we've reached an entry without accepting. Reload.
                accepted = false;
                break;
            }
            parents.push(...p);
        }
    }
    return accepted;
}
function hmrAcceptCheckOne(bundle /*: ParcelRequire */ , id /*: string */ , depsByBundle /*: ?{ [string]: { [string]: string } }*/ ) {
    var modules = bundle.modules;
    if (!modules) return;
    if (depsByBundle && !depsByBundle[bundle.HMR_BUNDLE_ID]) {
        // If we reached the root bundle without finding where the asset should go,
        // there's nothing to do. Mark as "accepted" so we don't reload the page.
        if (!bundle.parent) {
            bundleNotFound = true;
            return true;
        }
        return hmrAcceptCheckOne(bundle.parent, id, depsByBundle);
    }
    if (checkedAssets[id]) return null;
    checkedAssets[id] = true;
    var cached = bundle.cache[id];
    if (!cached) return true;
    assetsToDispose.push([
        bundle,
        id
    ]);
    if (cached && cached.hot && cached.hot._acceptCallbacks.length) {
        assetsToAccept.push([
            bundle,
            id
        ]);
        return true;
    }
    return false;
}
function hmrDisposeQueue() {
    // Dispose all old assets.
    for(let i = 0; i < assetsToDispose.length; i++){
        let id = assetsToDispose[i][1];
        if (!disposedAssets[id]) {
            hmrDispose(assetsToDispose[i][0], id);
            disposedAssets[id] = true;
        }
    }
    assetsToDispose = [];
}
function hmrDispose(bundle /*: ParcelRequire */ , id /*: string */ ) {
    var cached = bundle.cache[id];
    bundle.hotData[id] = {};
    if (cached && cached.hot) cached.hot.data = bundle.hotData[id];
    if (cached && cached.hot && cached.hot._disposeCallbacks.length) cached.hot._disposeCallbacks.forEach(function(cb) {
        cb(bundle.hotData[id]);
    });
    delete bundle.cache[id];
}
function hmrAccept(bundle /*: ParcelRequire */ , id /*: string */ ) {
    // Execute the module.
    bundle(id);
    // Run the accept callbacks in the new version of the module.
    var cached = bundle.cache[id];
    if (cached && cached.hot && cached.hot._acceptCallbacks.length) {
        let assetsToAlsoAccept = [];
        cached.hot._acceptCallbacks.forEach(function(cb) {
            let additionalAssets = cb(function() {
                return getParents(module.bundle.root, id);
            });
            if (Array.isArray(additionalAssets) && additionalAssets.length) assetsToAlsoAccept.push(...additionalAssets);
        });
        if (assetsToAlsoAccept.length) {
            let handled = assetsToAlsoAccept.every(function(a) {
                return hmrAcceptCheck(a[0], a[1]);
            });
            if (!handled) return fullReload();
            hmrDisposeQueue();
        }
    }
}

},{}],"nEvnq":[function(require,module,exports,__globalThis) {
/*!-----------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Version: 0.52.2(404545bded1df6ffa41ea0af4e8ddb219018c6c1)
 * Released under the MIT license
 * https://github.com/microsoft/monaco-editor/blob/main/LICENSE.txt
 *-----------------------------------------------------------------------------*/ // src/basic-languages/postiats/postiats.ts
var parcelHelpers = require("@parcel/transformer-js/src/esmodule-helpers.js");
parcelHelpers.defineInteropFlag(exports);
parcelHelpers.export(exports, "conf", ()=>conf);
parcelHelpers.export(exports, "language", ()=>language);
var conf = {
    comments: {
        lineComment: "//",
        blockComment: [
            "(*",
            "*)"
        ]
    },
    brackets: [
        [
            "{",
            "}"
        ],
        [
            "[",
            "]"
        ],
        [
            "(",
            ")"
        ],
        [
            "<",
            ">"
        ]
    ],
    autoClosingPairs: [
        {
            open: '"',
            close: '"',
            notIn: [
                "string",
                "comment"
            ]
        },
        {
            open: "{",
            close: "}",
            notIn: [
                "string",
                "comment"
            ]
        },
        {
            open: "[",
            close: "]",
            notIn: [
                "string",
                "comment"
            ]
        },
        {
            open: "(",
            close: ")",
            notIn: [
                "string",
                "comment"
            ]
        }
    ]
};
var language = {
    tokenPostfix: ".pats",
    // TODO: staload and dynload are followed by a special kind of string literals
    // with {$IDENTIFER} variables, and it also may make sense to highlight
    // the punctuation (. and / and \) differently.
    // Set defaultToken to invalid to see what you do not tokenize yet
    defaultToken: "invalid",
    // keyword reference: https://github.com/githwxi/ATS-Postiats/blob/master/src/pats_lexing_token.dats
    keywords: [
        //
        "abstype",
        // ABSTYPE
        "abst0ype",
        // ABST0YPE
        "absprop",
        // ABSPROP
        "absview",
        // ABSVIEW
        "absvtype",
        // ABSVIEWTYPE
        "absviewtype",
        // ABSVIEWTYPE
        "absvt0ype",
        // ABSVIEWT0YPE
        "absviewt0ype",
        // ABSVIEWT0YPE
        //
        "as",
        // T_AS
        //
        "and",
        // T_AND
        //
        "assume",
        // T_ASSUME
        //
        "begin",
        // T_BEGIN
        //
        /*
    		"case", // CASE
    */ //
        "classdec",
        // T_CLASSDEC
        //
        "datasort",
        // T_DATASORT
        //
        "datatype",
        // DATATYPE
        "dataprop",
        // DATAPROP
        "dataview",
        // DATAVIEW
        "datavtype",
        // DATAVIEWTYPE
        "dataviewtype",
        // DATAVIEWTYPE
        //
        "do",
        // T_DO
        //
        "end",
        // T_END
        //
        "extern",
        // T_EXTERN
        "extype",
        // T_EXTYPE
        "extvar",
        // T_EXTVAR
        //
        "exception",
        // T_EXCEPTION
        //
        "fn",
        // FN // non-recursive
        "fnx",
        // FNX // mutual tail-rec.
        "fun",
        // FUN // general-recursive
        //
        "prfn",
        // PRFN
        "prfun",
        // PRFUN
        //
        "praxi",
        // PRAXI
        "castfn",
        // CASTFN
        //
        "if",
        // T_IF
        "then",
        // T_THEN
        "else",
        // T_ELSE
        //
        "ifcase",
        // T_IFCASE
        //
        "in",
        // T_IN
        //
        "infix",
        // INFIX
        "infixl",
        // INFIXL
        "infixr",
        // INFIXR
        "prefix",
        // PREFIX
        "postfix",
        // POSTFIX
        //
        "implmnt",
        // IMPLMNT // 0
        "implement",
        // IMPLEMENT // 1
        //
        "primplmnt",
        // PRIMPLMNT // ~1
        "primplement",
        // PRIMPLMNT // ~1
        //
        "import",
        // T_IMPORT // for importing packages
        //
        /*
    		"lam", // LAM
    		"llam", // LLAM
    		"fix", // FIX
    */ //
        "let",
        // T_LET
        //
        "local",
        // T_LOCAL
        //
        "macdef",
        // MACDEF
        "macrodef",
        // MACRODEF
        //
        "nonfix",
        // T_NONFIX
        //
        "symelim",
        // T_SYMELIM
        "symintr",
        // T_SYMINTR
        "overload",
        // T_OVERLOAD
        //
        "of",
        // T_OF
        "op",
        // T_OP
        //
        "rec",
        // T_REC
        //
        "sif",
        // T_SIF
        "scase",
        // T_SCASE
        //
        "sortdef",
        // T_SORTDEF
        /*
    // HX: [sta] is now deprecated
    */ "sta",
        // T_STACST
        "stacst",
        // T_STACST
        "stadef",
        // T_STADEF
        "static",
        // T_STATIC
        /*
    		"stavar", // T_STAVAR
    */ //
        "staload",
        // T_STALOAD
        "dynload",
        // T_DYNLOAD
        //
        "try",
        // T_TRY
        //
        "tkindef",
        // T_TKINDEF // HX-2012-05-23
        //
        /*
    		"type", // TYPE
    */ "typedef",
        // TYPEDEF
        "propdef",
        // PROPDEF
        "viewdef",
        // VIEWDEF
        "vtypedef",
        // VIEWTYPEDEF
        "viewtypedef",
        // VIEWTYPEDEF
        //
        /*
    		"val", // VAL
    */ "prval",
        // PRVAL
        //
        "var",
        // VAR
        "prvar",
        // PRVAR
        //
        "when",
        // T_WHEN
        "where",
        // T_WHERE
        //
        /*
    		"for", // T_FOR
    		"while", // T_WHILE
    */ //
        "with",
        // T_WITH
        //
        "withtype",
        // WITHTYPE
        "withprop",
        // WITHPROP
        "withview",
        // WITHVIEW
        "withvtype",
        // WITHVIEWTYPE
        "withviewtype"
    ],
    keywords_dlr: [
        "$delay",
        // DLRDELAY
        "$ldelay",
        // DLRLDELAY
        //
        "$arrpsz",
        // T_DLRARRPSZ
        "$arrptrsize",
        // T_DLRARRPSZ
        //
        "$d2ctype",
        // T_DLRD2CTYPE
        //
        "$effmask",
        // DLREFFMASK
        "$effmask_ntm",
        // DLREFFMASK_NTM
        "$effmask_exn",
        // DLREFFMASK_EXN
        "$effmask_ref",
        // DLREFFMASK_REF
        "$effmask_wrt",
        // DLREFFMASK_WRT
        "$effmask_all",
        // DLREFFMASK_ALL
        //
        "$extern",
        // T_DLREXTERN
        "$extkind",
        // T_DLREXTKIND
        "$extype",
        // T_DLREXTYPE
        "$extype_struct",
        // T_DLREXTYPE_STRUCT
        //
        "$extval",
        // T_DLREXTVAL
        "$extfcall",
        // T_DLREXTFCALL
        "$extmcall",
        // T_DLREXTMCALL
        //
        "$literal",
        // T_DLRLITERAL
        //
        "$myfilename",
        // T_DLRMYFILENAME
        "$mylocation",
        // T_DLRMYLOCATION
        "$myfunction",
        // T_DLRMYFUNCTION
        //
        "$lst",
        // DLRLST
        "$lst_t",
        // DLRLST_T
        "$lst_vt",
        // DLRLST_VT
        "$list",
        // DLRLST
        "$list_t",
        // DLRLST_T
        "$list_vt",
        // DLRLST_VT
        //
        "$rec",
        // DLRREC
        "$rec_t",
        // DLRREC_T
        "$rec_vt",
        // DLRREC_VT
        "$record",
        // DLRREC
        "$record_t",
        // DLRREC_T
        "$record_vt",
        // DLRREC_VT
        //
        "$tup",
        // DLRTUP
        "$tup_t",
        // DLRTUP_T
        "$tup_vt",
        // DLRTUP_VT
        "$tuple",
        // DLRTUP
        "$tuple_t",
        // DLRTUP_T
        "$tuple_vt",
        // DLRTUP_VT
        //
        "$break",
        // T_DLRBREAK
        "$continue",
        // T_DLRCONTINUE
        //
        "$raise",
        // T_DLRRAISE
        //
        "$showtype",
        // T_DLRSHOWTYPE
        //
        "$vcopyenv_v",
        // DLRVCOPYENV_V
        "$vcopyenv_vt",
        // DLRVCOPYENV_VT
        //
        "$tempenver",
        // T_DLRTEMPENVER
        //
        "$solver_assert",
        // T_DLRSOLASSERT
        "$solver_verify"
    ],
    keywords_srp: [
        //
        "#if",
        // T_SRPIF
        "#ifdef",
        // T_SRPIFDEF
        "#ifndef",
        // T_SRPIFNDEF
        //
        "#then",
        // T_SRPTHEN
        //
        "#elif",
        // T_SRPELIF
        "#elifdef",
        // T_SRPELIFDEF
        "#elifndef",
        // T_SRPELIFNDEF
        //
        "#else",
        // T_SRPELSE
        "#endif",
        // T_SRPENDIF
        //
        "#error",
        // T_SRPERROR
        //
        "#prerr",
        // T_SRPPRERR // outpui to stderr
        "#print",
        // T_SRPPRINT // output to stdout
        //
        "#assert",
        // T_SRPASSERT
        //
        "#undef",
        // T_SRPUNDEF
        "#define",
        // T_SRPDEFINE
        //
        "#include",
        // T_SRPINCLUDE
        "#require",
        // T_SRPREQUIRE
        //
        "#pragma",
        // T_SRPPRAGMA // HX: general pragma
        "#codegen2",
        // T_SRPCODEGEN2 // for level-2 codegen
        "#codegen3"
    ],
    irregular_keyword_list: [
        "val+",
        "val-",
        "val",
        "case+",
        "case-",
        "case",
        "addr@",
        "addr",
        "fold@",
        "free@",
        "fix@",
        "fix",
        "lam@",
        "lam",
        "llam@",
        "llam",
        "viewt@ype+",
        "viewt@ype-",
        "viewt@ype",
        "viewtype+",
        "viewtype-",
        "viewtype",
        "view+",
        "view-",
        "view@",
        "view",
        "type+",
        "type-",
        "type",
        "vtype+",
        "vtype-",
        "vtype",
        "vt@ype+",
        "vt@ype-",
        "vt@ype",
        "viewt@ype+",
        "viewt@ype-",
        "viewt@ype",
        "viewtype+",
        "viewtype-",
        "viewtype",
        "prop+",
        "prop-",
        "prop",
        "type+",
        "type-",
        "type",
        "t@ype",
        "t@ype+",
        "t@ype-",
        "abst@ype",
        "abstype",
        "absviewt@ype",
        "absvt@ype",
        "for*",
        "for",
        "while*",
        "while"
    ],
    keywords_types: [
        "bool",
        "double",
        "byte",
        "int",
        "short",
        "char",
        "void",
        "unit",
        "long",
        "float",
        "string",
        "strptr"
    ],
    // TODO: reference for this?
    keywords_effects: [
        "0",
        // no effects
        "fun",
        "clo",
        "prf",
        "funclo",
        "cloptr",
        "cloref",
        "ref",
        "ntm",
        "1"
    ],
    operators: [
        "@",
        // T_AT
        "!",
        // T_BANG
        "|",
        // T_BAR
        "`",
        // T_BQUOTE
        ":",
        // T_COLON
        "$",
        // T_DOLLAR
        ".",
        // T_DOT
        "=",
        // T_EQ
        "#",
        // T_HASH
        "~",
        // T_TILDE
        //
        "..",
        // T_DOTDOT
        "...",
        // T_DOTDOTDOT
        //
        "=>",
        // T_EQGT
        // "=<", // T_EQLT
        "=<>",
        // T_EQLTGT
        "=/=>",
        // T_EQSLASHEQGT
        "=>>",
        // T_EQGTGT
        "=/=>>",
        // T_EQSLASHEQGTGT
        //
        "<",
        // T_LT // opening a tmparg
        ">",
        // T_GT // closing a tmparg
        //
        "><",
        // T_GTLT
        //
        ".<",
        // T_DOTLT
        ">.",
        // T_GTDOT
        //
        ".<>.",
        // T_DOTLTGTDOT
        //
        "->",
        // T_MINUSGT
        //"-<", // T_MINUSLT
        "-<>"
    ],
    brackets: [
        {
            open: ",(",
            close: ")",
            token: "delimiter.parenthesis"
        },
        // meta-programming syntax
        {
            open: "`(",
            close: ")",
            token: "delimiter.parenthesis"
        },
        {
            open: "%(",
            close: ")",
            token: "delimiter.parenthesis"
        },
        {
            open: "'(",
            close: ")",
            token: "delimiter.parenthesis"
        },
        {
            open: "'{",
            close: "}",
            token: "delimiter.parenthesis"
        },
        {
            open: "@(",
            close: ")",
            token: "delimiter.parenthesis"
        },
        {
            open: "@{",
            close: "}",
            token: "delimiter.brace"
        },
        {
            open: "@[",
            close: "]",
            token: "delimiter.square"
        },
        {
            open: "#[",
            close: "]",
            token: "delimiter.square"
        },
        {
            open: "{",
            close: "}",
            token: "delimiter.curly"
        },
        {
            open: "[",
            close: "]",
            token: "delimiter.square"
        },
        {
            open: "(",
            close: ")",
            token: "delimiter.parenthesis"
        },
        {
            open: "<",
            close: ">",
            token: "delimiter.angle"
        }
    ],
    // we include these common regular expressions
    symbols: /[=><!~?:&|+\-*\/\^%]+/,
    IDENTFST: /[a-zA-Z_]/,
    IDENTRST: /[a-zA-Z0-9_'$]/,
    symbolic: /[%&+-./:=@~`^|*!$#?<>]/,
    digit: /[0-9]/,
    digitseq0: /@digit*/,
    xdigit: /[0-9A-Za-z]/,
    xdigitseq0: /@xdigit*/,
    INTSP: /[lLuU]/,
    FLOATSP: /[fFlL]/,
    fexponent: /[eE][+-]?[0-9]+/,
    fexponent_bin: /[pP][+-]?[0-9]+/,
    deciexp: /\.[0-9]*@fexponent?/,
    hexiexp: /\.[0-9a-zA-Z]*@fexponent_bin?/,
    irregular_keywords: /val[+-]?|case[+-]?|addr\@?|fold\@|free\@|fix\@?|lam\@?|llam\@?|prop[+-]?|type[+-]?|view[+-@]?|viewt@?ype[+-]?|t@?ype[+-]?|v(iew)?t@?ype[+-]?|abst@?ype|absv(iew)?t@?ype|for\*?|while\*?/,
    ESCHAR: /[ntvbrfa\\\?'"\(\[\{]/,
    start: "root",
    // The main tokenizer for ATS/Postiats
    // reference: https://github.com/githwxi/ATS-Postiats/blob/master/src/pats_lexing.dats
    tokenizer: {
        root: [
            // lexing_blankseq0
            {
                regex: /[ \t\r\n]+/,
                action: {
                    token: ""
                }
            },
            // NOTE: (*) is an invalid ML-like comment!
            {
                regex: /\(\*\)/,
                action: {
                    token: "invalid"
                }
            },
            {
                regex: /\(\*/,
                action: {
                    token: "comment",
                    next: "lexing_COMMENT_block_ml"
                }
            },
            {
                regex: /\(/,
                action: "@brackets"
            },
            {
                regex: /\)/,
                action: "@brackets"
            },
            {
                regex: /\[/,
                action: "@brackets"
            },
            {
                regex: /\]/,
                action: "@brackets"
            },
            {
                regex: /\{/,
                action: "@brackets"
            },
            {
                regex: /\}/,
                action: "@brackets"
            },
            // lexing_COMMA
            {
                regex: /,\(/,
                action: "@brackets"
            },
            // meta-programming syntax
            {
                regex: /,/,
                action: {
                    token: "delimiter.comma"
                }
            },
            {
                regex: /;/,
                action: {
                    token: "delimiter.semicolon"
                }
            },
            // lexing_AT
            {
                regex: /@\(/,
                action: "@brackets"
            },
            {
                regex: /@\[/,
                action: "@brackets"
            },
            {
                regex: /@\{/,
                action: "@brackets"
            },
            // lexing_COLON
            {
                regex: /:</,
                action: {
                    token: "keyword",
                    next: "@lexing_EFFECT_commaseq0"
                }
            },
            // T_COLONLT
            /*
      			lexing_DOT:
      
      			. // SYMBOLIC => lexing_IDENT_sym
      			. FLOATDOT => lexing_FLOAT_deciexp
      			. DIGIT => T_DOTINT
      			*/ {
                regex: /\.@symbolic+/,
                action: {
                    token: "identifier.sym"
                }
            },
            // FLOATDOT case
            {
                regex: /\.@digit*@fexponent@FLOATSP*/,
                action: {
                    token: "number.float"
                }
            },
            {
                regex: /\.@digit+/,
                action: {
                    token: "number.float"
                }
            },
            // T_DOTINT
            // lexing_DOLLAR:
            // '$' IDENTFST IDENTRST* => lexing_IDENT_dlr, _ => lexing_IDENT_sym
            {
                regex: /\$@IDENTFST@IDENTRST*/,
                action: {
                    cases: {
                        "@keywords_dlr": {
                            token: "keyword.dlr"
                        },
                        "@default": {
                            token: "namespace"
                        }
                    }
                }
            },
            // lexing_SHARP:
            // '#' IDENTFST IDENTRST* => lexing_ident_srp, _ => lexing_IDENT_sym
            {
                regex: /\#@IDENTFST@IDENTRST*/,
                action: {
                    cases: {
                        "@keywords_srp": {
                            token: "keyword.srp"
                        },
                        "@default": {
                            token: "identifier"
                        }
                    }
                }
            },
            // lexing_PERCENT:
            {
                regex: /%\(/,
                action: {
                    token: "delimiter.parenthesis"
                }
            },
            {
                regex: /^%{(#|\^|\$)?/,
                action: {
                    token: "keyword",
                    next: "@lexing_EXTCODE",
                    nextEmbedded: "text/javascript"
                }
            },
            {
                regex: /^%}/,
                action: {
                    token: "keyword"
                }
            },
            // lexing_QUOTE
            {
                regex: /'\(/,
                action: {
                    token: "delimiter.parenthesis"
                }
            },
            {
                regex: /'\[/,
                action: {
                    token: "delimiter.bracket"
                }
            },
            {
                regex: /'\{/,
                action: {
                    token: "delimiter.brace"
                }
            },
            [
                /(')(\\@ESCHAR|\\[xX]@xdigit+|\\@digit+)(')/,
                [
                    "string",
                    "string.escape",
                    "string"
                ]
            ],
            [
                /'[^\\']'/,
                "string"
            ],
            // lexing_DQUOTE
            [
                /"/,
                "string.quote",
                "@lexing_DQUOTE"
            ],
            // lexing_BQUOTE
            {
                regex: /`\(/,
                action: "@brackets"
            },
            // TODO: otherwise, try lexing_IDENT_sym
            {
                regex: /\\/,
                action: {
                    token: "punctuation"
                }
            },
            // just T_BACKSLASH
            // lexing_IDENT_alp:
            // NOTE: (?!regex) is syntax for "not-followed-by" regex
            // to resolve ambiguity such as foreach$fwork being incorrectly lexed as [for] [each$fwork]!
            {
                regex: /@irregular_keywords(?!@IDENTRST)/,
                action: {
                    token: "keyword"
                }
            },
            {
                regex: /@IDENTFST@IDENTRST*[<!\[]?/,
                action: {
                    cases: {
                        // TODO: dynload and staload should be specially parsed
                        // dynload whitespace+ "special_string"
                        // this special string is really:
                        //  '/' '\\' '.' => punctuation
                        // ({\$)([a-zA-Z_][a-zA-Z_0-9]*)(}) => punctuation,keyword,punctuation
                        // [^"] => identifier/literal
                        "@keywords": {
                            token: "keyword"
                        },
                        "@keywords_types": {
                            token: "type"
                        },
                        "@default": {
                            token: "identifier"
                        }
                    }
                }
            },
            // lexing_IDENT_sym:
            {
                regex: /\/\/\/\//,
                action: {
                    token: "comment",
                    next: "@lexing_COMMENT_rest"
                }
            },
            {
                regex: /\/\/.*$/,
                action: {
                    token: "comment"
                }
            },
            {
                regex: /\/\*/,
                action: {
                    token: "comment",
                    next: "@lexing_COMMENT_block_c"
                }
            },
            // AS-20160627: specifically for effect annotations
            {
                regex: /-<|=</,
                action: {
                    token: "keyword",
                    next: "@lexing_EFFECT_commaseq0"
                }
            },
            {
                regex: /@symbolic+/,
                action: {
                    cases: {
                        "@operators": "keyword",
                        "@default": "operator"
                    }
                }
            },
            // lexing_ZERO:
            // FIXME: this one is quite messy/unfinished yet
            // TODO: lexing_INT_hex
            // - testing_hexiexp => lexing_FLOAT_hexiexp
            // - testing_fexponent_bin => lexing_FLOAT_hexiexp
            // - testing_intspseq0 => T_INT_hex
            // lexing_INT_hex:
            {
                regex: /0[xX]@xdigit+(@hexiexp|@fexponent_bin)@FLOATSP*/,
                action: {
                    token: "number.float"
                }
            },
            {
                regex: /0[xX]@xdigit+@INTSP*/,
                action: {
                    token: "number.hex"
                }
            },
            {
                regex: /0[0-7]+(?![0-9])@INTSP*/,
                action: {
                    token: "number.octal"
                }
            },
            // lexing_INT_oct
            //{regex: /0/, action: { token: 'number' } }, // INTZERO
            // lexing_INT_dec:
            // - testing_deciexp => lexing_FLOAT_deciexp
            // - testing_fexponent => lexing_FLOAT_deciexp
            // - otherwise => intspseq0 ([0-9]*[lLuU]?)
            {
                regex: /@digit+(@fexponent|@deciexp)@FLOATSP*/,
                action: {
                    token: "number.float"
                }
            },
            {
                regex: /@digit@digitseq0@INTSP*/,
                action: {
                    token: "number.decimal"
                }
            },
            // DIGIT, if followed by digitseq0, is lexing_INT_dec
            {
                regex: /@digit+@INTSP*/,
                action: {
                    token: "number"
                }
            }
        ],
        lexing_COMMENT_block_ml: [
            [
                /[^\(\*]+/,
                "comment"
            ],
            [
                /\(\*/,
                "comment",
                "@push"
            ],
            [
                /\(\*/,
                "comment.invalid"
            ],
            [
                /\*\)/,
                "comment",
                "@pop"
            ],
            [
                /\*/,
                "comment"
            ]
        ],
        lexing_COMMENT_block_c: [
            [
                /[^\/*]+/,
                "comment"
            ],
            // [/\/\*/, 'comment', '@push' ],    // nested C-style block comments not allowed
            // [/\/\*/,    'comment.invalid' ],	// NOTE: this breaks block comments in the shape of /* //*/
            [
                /\*\//,
                "comment",
                "@pop"
            ],
            [
                /[\/*]/,
                "comment"
            ]
        ],
        lexing_COMMENT_rest: [
            [
                /$/,
                "comment",
                "@pop"
            ],
            // FIXME: does it match? docs say 'no'
            [
                /.*/,
                "comment"
            ]
        ],
        // NOTE: added by AS, specifically for highlighting
        lexing_EFFECT_commaseq0: [
            {
                regex: /@IDENTFST@IDENTRST+|@digit+/,
                action: {
                    cases: {
                        "@keywords_effects": {
                            token: "type.effect"
                        },
                        "@default": {
                            token: "identifier"
                        }
                    }
                }
            },
            {
                regex: /,/,
                action: {
                    token: "punctuation"
                }
            },
            {
                regex: />/,
                action: {
                    token: "@rematch",
                    next: "@pop"
                }
            }
        ],
        lexing_EXTCODE: [
            {
                regex: /^%}/,
                action: {
                    token: "@rematch",
                    next: "@pop",
                    nextEmbedded: "@pop"
                }
            },
            {
                regex: /[^%]+/,
                action: ""
            }
        ],
        lexing_DQUOTE: [
            {
                regex: /"/,
                action: {
                    token: "string.quote",
                    next: "@pop"
                }
            },
            // AS-20160628: additional hi-lighting for variables in staload/dynload strings
            {
                regex: /(\{\$)(@IDENTFST@IDENTRST*)(\})/,
                action: [
                    {
                        token: "string.escape"
                    },
                    {
                        token: "identifier"
                    },
                    {
                        token: "string.escape"
                    }
                ]
            },
            {
                regex: /\\$/,
                action: {
                    token: "string.escape"
                }
            },
            {
                regex: /\\(@ESCHAR|[xX]@xdigit+|@digit+)/,
                action: {
                    token: "string.escape"
                }
            },
            {
                regex: /[^\\"]+/,
                action: {
                    token: "string"
                }
            }
        ]
    }
};

},{"@parcel/transformer-js/src/esmodule-helpers.js":"jnFvT"}]},["gigho"], null, "parcelRequire8661", {})

//# sourceMappingURL=postiats.c9dbe71c.js.map
