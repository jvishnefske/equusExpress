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
})({"8MYlh":[function(require,module,exports,__globalThis) {
var global = arguments[3];
var HMR_HOST = null;
var HMR_PORT = null;
var HMR_SERVER_PORT = 1234;
var HMR_SECURE = false;
var HMR_ENV_HASH = "439701173a9199ea";
var HMR_USE_SSE = false;
module.bundle.HMR_BUNDLE_ID = "87f5f88f5ab65394";
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

},{}],"UjesR":[function(require,module,exports,__globalThis) {
/*!-----------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Version: 0.52.2(404545bded1df6ffa41ea0af4e8ddb219018c6c1)
 * Released under the MIT license
 * https://github.com/microsoft/monaco-editor/blob/main/LICENSE.txt
 *-----------------------------------------------------------------------------*/ // src/basic-languages/clojure/clojure.ts
var parcelHelpers = require("@parcel/transformer-js/src/esmodule-helpers.js");
parcelHelpers.defineInteropFlag(exports);
parcelHelpers.export(exports, "conf", ()=>conf);
parcelHelpers.export(exports, "language", ()=>language);
var conf = {
    comments: {
        lineComment: ";;"
    },
    brackets: [
        [
            "[",
            "]"
        ],
        [
            "(",
            ")"
        ],
        [
            "{",
            "}"
        ]
    ],
    autoClosingPairs: [
        {
            open: "[",
            close: "]"
        },
        {
            open: '"',
            close: '"'
        },
        {
            open: "(",
            close: ")"
        },
        {
            open: "{",
            close: "}"
        }
    ],
    surroundingPairs: [
        {
            open: "[",
            close: "]"
        },
        {
            open: '"',
            close: '"'
        },
        {
            open: "(",
            close: ")"
        },
        {
            open: "{",
            close: "}"
        }
    ]
};
var language = {
    defaultToken: "",
    ignoreCase: true,
    tokenPostfix: ".clj",
    brackets: [
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
            open: "{",
            close: "}",
            token: "delimiter.curly"
        }
    ],
    constants: [
        "true",
        "false",
        "nil"
    ],
    // delimiters: /[\\\[\]\s"#'(),;@^`{}~]|$/,
    numbers: /^(?:[+\-]?\d+(?:(?:N|(?:[eE][+\-]?\d+))|(?:\.?\d*(?:M|(?:[eE][+\-]?\d+))?)|\/\d+|[xX][0-9a-fA-F]+|r[0-9a-zA-Z]+)?(?=[\\\[\]\s"#'(),;@^`{}~]|$))/,
    characters: /^(?:\\(?:backspace|formfeed|newline|return|space|tab|o[0-7]{3}|u[0-9A-Fa-f]{4}|x[0-9A-Fa-f]{4}|.)?(?=[\\\[\]\s"(),;@^`{}~]|$))/,
    escapes: /^\\(?:["'\\bfnrt]|x[0-9A-Fa-f]{1,4}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})/,
    // simple-namespace := /^[^\\\/\[\]\d\s"#'(),;@^`{}~][^\\\[\]\s"(),;@^`{}~]*/
    // simple-symbol    := /^(?:\/|[^\\\/\[\]\d\s"#'(),;@^`{}~][^\\\[\]\s"(),;@^`{}~]*)/
    // qualified-symbol := (<simple-namespace>(<.><simple-namespace>)*</>)?<simple-symbol>
    qualifiedSymbols: /^(?:(?:[^\\\/\[\]\d\s"#'(),;@^`{}~][^\\\[\]\s"(),;@^`{}~]*(?:\.[^\\\/\[\]\d\s"#'(),;@^`{}~][^\\\[\]\s"(),;@^`{}~]*)*\/)?(?:\/|[^\\\/\[\]\d\s"#'(),;@^`{}~][^\\\[\]\s"(),;@^`{}~]*)*(?=[\\\[\]\s"(),;@^`{}~]|$))/,
    specialForms: [
        ".",
        "catch",
        "def",
        "do",
        "if",
        "monitor-enter",
        "monitor-exit",
        "new",
        "quote",
        "recur",
        "set!",
        "throw",
        "try",
        "var"
    ],
    coreSymbols: [
        "*",
        "*'",
        "*1",
        "*2",
        "*3",
        "*agent*",
        "*allow-unresolved-vars*",
        "*assert*",
        "*clojure-version*",
        "*command-line-args*",
        "*compile-files*",
        "*compile-path*",
        "*compiler-options*",
        "*data-readers*",
        "*default-data-reader-fn*",
        "*e",
        "*err*",
        "*file*",
        "*flush-on-newline*",
        "*fn-loader*",
        "*in*",
        "*math-context*",
        "*ns*",
        "*out*",
        "*print-dup*",
        "*print-length*",
        "*print-level*",
        "*print-meta*",
        "*print-namespace-maps*",
        "*print-readably*",
        "*read-eval*",
        "*reader-resolver*",
        "*source-path*",
        "*suppress-read*",
        "*unchecked-math*",
        "*use-context-classloader*",
        "*verbose-defrecords*",
        "*warn-on-reflection*",
        "+",
        "+'",
        "-",
        "-'",
        "->",
        "->>",
        "->ArrayChunk",
        "->Eduction",
        "->Vec",
        "->VecNode",
        "->VecSeq",
        "-cache-protocol-fn",
        "-reset-methods",
        "..",
        "/",
        "<",
        "<=",
        "=",
        "==",
        ">",
        ">=",
        "EMPTY-NODE",
        "Inst",
        "StackTraceElement->vec",
        "Throwable->map",
        "accessor",
        "aclone",
        "add-classpath",
        "add-watch",
        "agent",
        "agent-error",
        "agent-errors",
        "aget",
        "alength",
        "alias",
        "all-ns",
        "alter",
        "alter-meta!",
        "alter-var-root",
        "amap",
        "ancestors",
        "and",
        "any?",
        "apply",
        "areduce",
        "array-map",
        "as->",
        "aset",
        "aset-boolean",
        "aset-byte",
        "aset-char",
        "aset-double",
        "aset-float",
        "aset-int",
        "aset-long",
        "aset-short",
        "assert",
        "assoc",
        "assoc!",
        "assoc-in",
        "associative?",
        "atom",
        "await",
        "await-for",
        "await1",
        "bases",
        "bean",
        "bigdec",
        "bigint",
        "biginteger",
        "binding",
        "bit-and",
        "bit-and-not",
        "bit-clear",
        "bit-flip",
        "bit-not",
        "bit-or",
        "bit-set",
        "bit-shift-left",
        "bit-shift-right",
        "bit-test",
        "bit-xor",
        "boolean",
        "boolean-array",
        "boolean?",
        "booleans",
        "bound-fn",
        "bound-fn*",
        "bound?",
        "bounded-count",
        "butlast",
        "byte",
        "byte-array",
        "bytes",
        "bytes?",
        "case",
        "cast",
        "cat",
        "char",
        "char-array",
        "char-escape-string",
        "char-name-string",
        "char?",
        "chars",
        "chunk",
        "chunk-append",
        "chunk-buffer",
        "chunk-cons",
        "chunk-first",
        "chunk-next",
        "chunk-rest",
        "chunked-seq?",
        "class",
        "class?",
        "clear-agent-errors",
        "clojure-version",
        "coll?",
        "comment",
        "commute",
        "comp",
        "comparator",
        "compare",
        "compare-and-set!",
        "compile",
        "complement",
        "completing",
        "concat",
        "cond",
        "cond->",
        "cond->>",
        "condp",
        "conj",
        "conj!",
        "cons",
        "constantly",
        "construct-proxy",
        "contains?",
        "count",
        "counted?",
        "create-ns",
        "create-struct",
        "cycle",
        "dec",
        "dec'",
        "decimal?",
        "declare",
        "dedupe",
        "default-data-readers",
        "definline",
        "definterface",
        "defmacro",
        "defmethod",
        "defmulti",
        "defn",
        "defn-",
        "defonce",
        "defprotocol",
        "defrecord",
        "defstruct",
        "deftype",
        "delay",
        "delay?",
        "deliver",
        "denominator",
        "deref",
        "derive",
        "descendants",
        "destructure",
        "disj",
        "disj!",
        "dissoc",
        "dissoc!",
        "distinct",
        "distinct?",
        "doall",
        "dorun",
        "doseq",
        "dosync",
        "dotimes",
        "doto",
        "double",
        "double-array",
        "double?",
        "doubles",
        "drop",
        "drop-last",
        "drop-while",
        "eduction",
        "empty",
        "empty?",
        "ensure",
        "ensure-reduced",
        "enumeration-seq",
        "error-handler",
        "error-mode",
        "eval",
        "even?",
        "every-pred",
        "every?",
        "ex-data",
        "ex-info",
        "extend",
        "extend-protocol",
        "extend-type",
        "extenders",
        "extends?",
        "false?",
        "ffirst",
        "file-seq",
        "filter",
        "filterv",
        "find",
        "find-keyword",
        "find-ns",
        "find-protocol-impl",
        "find-protocol-method",
        "find-var",
        "first",
        "flatten",
        "float",
        "float-array",
        "float?",
        "floats",
        "flush",
        "fn",
        "fn?",
        "fnext",
        "fnil",
        "for",
        "force",
        "format",
        "frequencies",
        "future",
        "future-call",
        "future-cancel",
        "future-cancelled?",
        "future-done?",
        "future?",
        "gen-class",
        "gen-interface",
        "gensym",
        "get",
        "get-in",
        "get-method",
        "get-proxy-class",
        "get-thread-bindings",
        "get-validator",
        "group-by",
        "halt-when",
        "hash",
        "hash-combine",
        "hash-map",
        "hash-ordered-coll",
        "hash-set",
        "hash-unordered-coll",
        "ident?",
        "identical?",
        "identity",
        "if-let",
        "if-not",
        "if-some",
        "ifn?",
        "import",
        "in-ns",
        "inc",
        "inc'",
        "indexed?",
        "init-proxy",
        "inst-ms",
        "inst-ms*",
        "inst?",
        "instance?",
        "int",
        "int-array",
        "int?",
        "integer?",
        "interleave",
        "intern",
        "interpose",
        "into",
        "into-array",
        "ints",
        "io!",
        "isa?",
        "iterate",
        "iterator-seq",
        "juxt",
        "keep",
        "keep-indexed",
        "key",
        "keys",
        "keyword",
        "keyword?",
        "last",
        "lazy-cat",
        "lazy-seq",
        "let",
        "letfn",
        "line-seq",
        "list",
        "list*",
        "list?",
        "load",
        "load-file",
        "load-reader",
        "load-string",
        "loaded-libs",
        "locking",
        "long",
        "long-array",
        "longs",
        "loop",
        "macroexpand",
        "macroexpand-1",
        "make-array",
        "make-hierarchy",
        "map",
        "map-entry?",
        "map-indexed",
        "map?",
        "mapcat",
        "mapv",
        "max",
        "max-key",
        "memfn",
        "memoize",
        "merge",
        "merge-with",
        "meta",
        "method-sig",
        "methods",
        "min",
        "min-key",
        "mix-collection-hash",
        "mod",
        "munge",
        "name",
        "namespace",
        "namespace-munge",
        "nat-int?",
        "neg-int?",
        "neg?",
        "newline",
        "next",
        "nfirst",
        "nil?",
        "nnext",
        "not",
        "not-any?",
        "not-empty",
        "not-every?",
        "not=",
        "ns",
        "ns-aliases",
        "ns-imports",
        "ns-interns",
        "ns-map",
        "ns-name",
        "ns-publics",
        "ns-refers",
        "ns-resolve",
        "ns-unalias",
        "ns-unmap",
        "nth",
        "nthnext",
        "nthrest",
        "num",
        "number?",
        "numerator",
        "object-array",
        "odd?",
        "or",
        "parents",
        "partial",
        "partition",
        "partition-all",
        "partition-by",
        "pcalls",
        "peek",
        "persistent!",
        "pmap",
        "pop",
        "pop!",
        "pop-thread-bindings",
        "pos-int?",
        "pos?",
        "pr",
        "pr-str",
        "prefer-method",
        "prefers",
        "primitives-classnames",
        "print",
        "print-ctor",
        "print-dup",
        "print-method",
        "print-simple",
        "print-str",
        "printf",
        "println",
        "println-str",
        "prn",
        "prn-str",
        "promise",
        "proxy",
        "proxy-call-with-super",
        "proxy-mappings",
        "proxy-name",
        "proxy-super",
        "push-thread-bindings",
        "pvalues",
        "qualified-ident?",
        "qualified-keyword?",
        "qualified-symbol?",
        "quot",
        "rand",
        "rand-int",
        "rand-nth",
        "random-sample",
        "range",
        "ratio?",
        "rational?",
        "rationalize",
        "re-find",
        "re-groups",
        "re-matcher",
        "re-matches",
        "re-pattern",
        "re-seq",
        "read",
        "read-line",
        "read-string",
        "reader-conditional",
        "reader-conditional?",
        "realized?",
        "record?",
        "reduce",
        "reduce-kv",
        "reduced",
        "reduced?",
        "reductions",
        "ref",
        "ref-history-count",
        "ref-max-history",
        "ref-min-history",
        "ref-set",
        "refer",
        "refer-clojure",
        "reify",
        "release-pending-sends",
        "rem",
        "remove",
        "remove-all-methods",
        "remove-method",
        "remove-ns",
        "remove-watch",
        "repeat",
        "repeatedly",
        "replace",
        "replicate",
        "require",
        "reset!",
        "reset-meta!",
        "reset-vals!",
        "resolve",
        "rest",
        "restart-agent",
        "resultset-seq",
        "reverse",
        "reversible?",
        "rseq",
        "rsubseq",
        "run!",
        "satisfies?",
        "second",
        "select-keys",
        "send",
        "send-off",
        "send-via",
        "seq",
        "seq?",
        "seqable?",
        "seque",
        "sequence",
        "sequential?",
        "set",
        "set-agent-send-executor!",
        "set-agent-send-off-executor!",
        "set-error-handler!",
        "set-error-mode!",
        "set-validator!",
        "set?",
        "short",
        "short-array",
        "shorts",
        "shuffle",
        "shutdown-agents",
        "simple-ident?",
        "simple-keyword?",
        "simple-symbol?",
        "slurp",
        "some",
        "some->",
        "some->>",
        "some-fn",
        "some?",
        "sort",
        "sort-by",
        "sorted-map",
        "sorted-map-by",
        "sorted-set",
        "sorted-set-by",
        "sorted?",
        "special-symbol?",
        "spit",
        "split-at",
        "split-with",
        "str",
        "string?",
        "struct",
        "struct-map",
        "subs",
        "subseq",
        "subvec",
        "supers",
        "swap!",
        "swap-vals!",
        "symbol",
        "symbol?",
        "sync",
        "tagged-literal",
        "tagged-literal?",
        "take",
        "take-last",
        "take-nth",
        "take-while",
        "test",
        "the-ns",
        "thread-bound?",
        "time",
        "to-array",
        "to-array-2d",
        "trampoline",
        "transduce",
        "transient",
        "tree-seq",
        "true?",
        "type",
        "unchecked-add",
        "unchecked-add-int",
        "unchecked-byte",
        "unchecked-char",
        "unchecked-dec",
        "unchecked-dec-int",
        "unchecked-divide-int",
        "unchecked-double",
        "unchecked-float",
        "unchecked-inc",
        "unchecked-inc-int",
        "unchecked-int",
        "unchecked-long",
        "unchecked-multiply",
        "unchecked-multiply-int",
        "unchecked-negate",
        "unchecked-negate-int",
        "unchecked-remainder-int",
        "unchecked-short",
        "unchecked-subtract",
        "unchecked-subtract-int",
        "underive",
        "unquote",
        "unquote-splicing",
        "unreduced",
        "unsigned-bit-shift-right",
        "update",
        "update-in",
        "update-proxy",
        "uri?",
        "use",
        "uuid?",
        "val",
        "vals",
        "var-get",
        "var-set",
        "var?",
        "vary-meta",
        "vec",
        "vector",
        "vector-of",
        "vector?",
        "volatile!",
        "volatile?",
        "vreset!",
        "vswap!",
        "when",
        "when-first",
        "when-let",
        "when-not",
        "when-some",
        "while",
        "with-bindings",
        "with-bindings*",
        "with-in-str",
        "with-loading-context",
        "with-local-vars",
        "with-meta",
        "with-open",
        "with-out-str",
        "with-precision",
        "with-redefs",
        "with-redefs-fn",
        "xml-seq",
        "zero?",
        "zipmap"
    ],
    tokenizer: {
        root: [
            // whitespaces and comments
            {
                include: "@whitespace"
            },
            // numbers
            [
                /@numbers/,
                "number"
            ],
            // characters
            [
                /@characters/,
                "string"
            ],
            // strings
            {
                include: "@string"
            },
            // brackets
            [
                /[()\[\]{}]/,
                "@brackets"
            ],
            // regular expressions
            [
                /\/#"(?:\.|(?:")|[^"\n])*"\/g/,
                "regexp"
            ],
            // reader macro characters
            [
                /[#'@^`~]/,
                "meta"
            ],
            // symbols
            [
                /@qualifiedSymbols/,
                {
                    cases: {
                        "^:.+$": "constant",
                        // Clojure keywords (e.g., `:foo/bar`)
                        "@specialForms": "keyword",
                        "@coreSymbols": "keyword",
                        "@constants": "constant",
                        "@default": "identifier"
                    }
                }
            ]
        ],
        whitespace: [
            [
                /[\s,]+/,
                "white"
            ],
            [
                /;.*$/,
                "comment"
            ],
            [
                /\(comment\b/,
                "comment",
                "@comment"
            ]
        ],
        comment: [
            [
                /\(/,
                "comment",
                "@push"
            ],
            [
                /\)/,
                "comment",
                "@pop"
            ],
            [
                /[^()]/,
                "comment"
            ]
        ],
        string: [
            [
                /"/,
                "string",
                "@multiLineString"
            ]
        ],
        multiLineString: [
            [
                /"/,
                "string",
                "@popall"
            ],
            [
                /@escapes/,
                "string.escape"
            ],
            [
                /./,
                "string"
            ]
        ]
    }
};

},{"@parcel/transformer-js/src/esmodule-helpers.js":"jnFvT"}]},["8MYlh"], null, "parcelRequire8661", {})

//# sourceMappingURL=clojure.5ab65394.js.map
