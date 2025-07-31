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
})({"gaUzL":[function(require,module,exports,__globalThis) {
var global = arguments[3];
var HMR_HOST = null;
var HMR_PORT = null;
var HMR_SERVER_PORT = 1234;
var HMR_SECURE = false;
var HMR_ENV_HASH = "439701173a9199ea";
var HMR_USE_SSE = false;
module.bundle.HMR_BUNDLE_ID = "1959cde482877aae";
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

},{}],"j2dnn":[function(require,module,exports,__globalThis) {
/*!-----------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Version: 0.52.2(404545bded1df6ffa41ea0af4e8ddb219018c6c1)
 * Released under the MIT license
 * https://github.com/microsoft/monaco-editor/blob/main/LICENSE.txt
 *-----------------------------------------------------------------------------*/ var parcelHelpers = require("@parcel/transformer-js/src/esmodule-helpers.js");
parcelHelpers.defineInteropFlag(exports);
parcelHelpers.export(exports, "TagAngleInterpolationBracket", ()=>TagAngleInterpolationBracket);
parcelHelpers.export(exports, "TagAngleInterpolationDollar", ()=>TagAngleInterpolationDollar);
parcelHelpers.export(exports, "TagAutoInterpolationBracket", ()=>TagAutoInterpolationBracket);
parcelHelpers.export(exports, "TagAutoInterpolationDollar", ()=>TagAutoInterpolationDollar);
parcelHelpers.export(exports, "TagBracketInterpolationBracket", ()=>TagBracketInterpolationBracket);
parcelHelpers.export(exports, "TagBracketInterpolationDollar", ()=>TagBracketInterpolationDollar);
var _editorApiJs = require("../../editor/editor.api.js");
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc)=>{
    if (from && typeof from === "object" || typeof from === "function") {
        for (let key of __getOwnPropNames(from))if (!__hasOwnProp.call(to, key) && key !== except) __defProp(to, key, {
            get: ()=>from[key],
            enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable
        });
    }
    return to;
};
var __reExport = (target, mod, secondTarget)=>(__copyProps(target, mod, "default"), secondTarget && __copyProps(secondTarget, mod, "default"));
// src/fillers/monaco-editor-core.ts
var monaco_editor_core_exports = {};
__reExport(monaco_editor_core_exports, _editorApiJs);
// src/basic-languages/freemarker2/freemarker2.ts
var EMPTY_ELEMENTS = [
    "assign",
    "flush",
    "ftl",
    "return",
    "global",
    "import",
    "include",
    "break",
    "continue",
    "local",
    "nested",
    "nt",
    "setting",
    "stop",
    "t",
    "lt",
    "rt",
    "fallback"
];
var BLOCK_ELEMENTS = [
    "attempt",
    "autoesc",
    "autoEsc",
    "compress",
    "comment",
    "escape",
    "noescape",
    "function",
    "if",
    "list",
    "items",
    "sep",
    "macro",
    "noparse",
    "noParse",
    "noautoesc",
    "noAutoEsc",
    "outputformat",
    "switch",
    "visit",
    "recurse"
];
var TagSyntaxAngle = {
    close: ">",
    id: "angle",
    open: "<"
};
var TagSyntaxBracket = {
    close: "\\]",
    id: "bracket",
    open: "\\["
};
var TagSyntaxAuto = {
    close: "[>\\]]",
    id: "auto",
    open: "[<\\[]"
};
var InterpolationSyntaxDollar = {
    close: "\\}",
    id: "dollar",
    open1: "\\$",
    open2: "\\{"
};
var InterpolationSyntaxBracket = {
    close: "\\]",
    id: "bracket",
    open1: "\\[",
    open2: "="
};
function createLangConfiguration(ts) {
    return {
        brackets: [
            [
                "<",
                ">"
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
                "{",
                "}"
            ]
        ],
        comments: {
            blockComment: [
                `${ts.open}--`,
                `--${ts.close}`
            ]
        },
        autoCloseBefore: "\n\r	 }]),.:;=",
        autoClosingPairs: [
            {
                open: "{",
                close: "}"
            },
            {
                open: "[",
                close: "]"
            },
            {
                open: "(",
                close: ")"
            },
            {
                open: '"',
                close: '"',
                notIn: [
                    "string"
                ]
            },
            {
                open: "'",
                close: "'",
                notIn: [
                    "string"
                ]
            }
        ],
        surroundingPairs: [
            {
                open: '"',
                close: '"'
            },
            {
                open: "'",
                close: "'"
            },
            {
                open: "{",
                close: "}"
            },
            {
                open: "[",
                close: "]"
            },
            {
                open: "(",
                close: ")"
            },
            {
                open: "<",
                close: ">"
            }
        ],
        folding: {
            markers: {
                start: new RegExp(`${ts.open}#(?:${BLOCK_ELEMENTS.join("|")})([^/${ts.close}]*(?!/)${ts.close})[^${ts.open}]*$`),
                end: new RegExp(`${ts.open}/#(?:${BLOCK_ELEMENTS.join("|")})[\\r\\n\\t ]*>`)
            }
        },
        onEnterRules: [
            {
                beforeText: new RegExp(`${ts.open}#(?!(?:${EMPTY_ELEMENTS.join("|")}))([a-zA-Z_]+)([^/${ts.close}]*(?!/)${ts.close})[^${ts.open}]*$`),
                afterText: new RegExp(`^${ts.open}/#([a-zA-Z_]+)[\\r\\n\\t ]*${ts.close}$`),
                action: {
                    indentAction: monaco_editor_core_exports.languages.IndentAction.IndentOutdent
                }
            },
            {
                beforeText: new RegExp(`${ts.open}#(?!(?:${EMPTY_ELEMENTS.join("|")}))([a-zA-Z_]+)([^/${ts.close}]*(?!/)${ts.close})[^${ts.open}]*$`),
                action: {
                    indentAction: monaco_editor_core_exports.languages.IndentAction.Indent
                }
            }
        ]
    };
}
function createLangConfigurationAuto() {
    return {
        // Cannot set block comment delimiter in auto mode...
        // It depends on the content and the cursor position of the file...
        brackets: [
            [
                "<",
                ">"
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
                "{",
                "}"
            ]
        ],
        autoCloseBefore: "\n\r	 }]),.:;=",
        autoClosingPairs: [
            {
                open: "{",
                close: "}"
            },
            {
                open: "[",
                close: "]"
            },
            {
                open: "(",
                close: ")"
            },
            {
                open: '"',
                close: '"',
                notIn: [
                    "string"
                ]
            },
            {
                open: "'",
                close: "'",
                notIn: [
                    "string"
                ]
            }
        ],
        surroundingPairs: [
            {
                open: '"',
                close: '"'
            },
            {
                open: "'",
                close: "'"
            },
            {
                open: "{",
                close: "}"
            },
            {
                open: "[",
                close: "]"
            },
            {
                open: "(",
                close: ")"
            },
            {
                open: "<",
                close: ">"
            }
        ],
        folding: {
            markers: {
                start: new RegExp(`[<\\[]#(?:${BLOCK_ELEMENTS.join("|")})([^/>\\]]*(?!/)[>\\]])[^<\\[]*$`),
                end: new RegExp(`[<\\[]/#(?:${BLOCK_ELEMENTS.join("|")})[\\r\\n\\t ]*>`)
            }
        },
        onEnterRules: [
            {
                beforeText: new RegExp(`[<\\[]#(?!(?:${EMPTY_ELEMENTS.join("|")}))([a-zA-Z_]+)([^/>\\]]*(?!/)[>\\]])[^[<\\[]]*$`),
                afterText: new RegExp(`^[<\\[]/#([a-zA-Z_]+)[\\r\\n\\t ]*[>\\]]$`),
                action: {
                    indentAction: monaco_editor_core_exports.languages.IndentAction.IndentOutdent
                }
            },
            {
                beforeText: new RegExp(`[<\\[]#(?!(?:${EMPTY_ELEMENTS.join("|")}))([a-zA-Z_]+)([^/>\\]]*(?!/)[>\\]])[^[<\\[]]*$`),
                action: {
                    indentAction: monaco_editor_core_exports.languages.IndentAction.Indent
                }
            }
        ]
    };
}
function createMonarchLanguage(ts, is) {
    const id = `_${ts.id}_${is.id}`;
    const s = (name)=>name.replace(/__id__/g, id);
    const r = (regexp)=>{
        const source = regexp.source.replace(/__id__/g, id);
        return new RegExp(source, regexp.flags);
    };
    return {
        // Settings
        unicode: true,
        includeLF: false,
        start: s("default__id__"),
        ignoreCase: false,
        defaultToken: "invalid",
        tokenPostfix: `.freemarker2`,
        brackets: [
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
        // Dynamic RegExp
        [s("open__id__")]: new RegExp(ts.open),
        [s("close__id__")]: new RegExp(ts.close),
        [s("iOpen1__id__")]: new RegExp(is.open1),
        [s("iOpen2__id__")]: new RegExp(is.open2),
        [s("iClose__id__")]: new RegExp(is.close),
        // <#START_TAG : "<" | "<#" | "[#">
        // <#END_TAG : "</" | "</#" | "[/#">
        [s("startTag__id__")]: r(/(@open__id__)(#)/),
        [s("endTag__id__")]: r(/(@open__id__)(\/#)/),
        [s("startOrEndTag__id__")]: r(/(@open__id__)(\/?#)/),
        // <#CLOSE_TAG1 : (<BLANK>)* (">" | "]")>
        [s("closeTag1__id__")]: r(/((?:@blank)*)(@close__id__)/),
        // <#CLOSE_TAG2 : (<BLANK>)* ("/")? (">" | "]")>
        [s("closeTag2__id__")]: r(/((?:@blank)*\/?)(@close__id__)/),
        // Static RegExp
        // <#BLANK : " " | "\t" | "\n" | "\r">
        blank: /[ \t\n\r]/,
        // <FALSE : "false">
        // <TRUE : "true">
        // <IN : "in">
        // <AS : "as">
        // <USING : "using">
        keywords: [
            "false",
            "true",
            "in",
            "as",
            "using"
        ],
        // Directive names that cannot have an expression parameters and cannot be self-closing
        // E.g. <#if id==2> ... </#if>
        directiveStartCloseTag1: /attempt|recover|sep|auto[eE]sc|no(?:autoe|AutoE)sc|compress|default|no[eE]scape|comment|no[pP]arse/,
        // Directive names that cannot have an expression parameter and can be self-closing
        // E.g. <#if> ... <#else>  ... </#if>
        // E.g. <#if> ... <#else /></#if>
        directiveStartCloseTag2: /else|break|continue|return|stop|flush|t|lt|rt|nt|nested|recurse|fallback|ftl/,
        // Directive names that can have an expression parameter and cannot be self-closing
        // E.g. <#if id==2> ... </#if>
        directiveStartBlank: /if|else[iI]f|list|for[eE]ach|switch|case|assign|global|local|include|import|function|macro|transform|visit|stop|return|call|setting|output[fF]ormat|nested|recurse|escape|ftl|items/,
        // Directive names that can have an end tag
        // E.g. </#if>
        directiveEndCloseTag1: /if|list|items|sep|recover|attempt|for[eE]ach|local|global|assign|function|macro|output[fF]ormat|auto[eE]sc|no(?:autoe|AutoE)sc|compress|transform|switch|escape|no[eE]scape/,
        // <#ESCAPED_CHAR :
        //     "\\"
        //     (
        //         ("n" | "t" | "r" | "f" | "b" | "g" | "l" | "a" | "\\" | "'" | "\"" | "{" | "=")
        //         |
        //         ("x" ["0"-"9", "A"-"F", "a"-"f"])
        //     )
        // >
        // Note: While the JavaCC tokenizer rule only specifies one hex digit,
        // FreeMarker actually interprets up to 4 hex digits.
        escapedChar: /\\(?:[ntrfbgla\\'"\{=]|(?:x[0-9A-Fa-f]{1,4}))/,
        // <#ASCII_DIGIT: ["0" - "9"]>
        asciiDigit: /[0-9]/,
        // <INTEGER : (["0"-"9"])+>
        integer: /[0-9]+/,
        // <#NON_ESCAPED_ID_START_CHAR:
        // [
        // 	  // This was generated on JDK 1.8.0_20 Win64 with src/main/misc/identifierChars/IdentifierCharGenerator.java
        //    ...
        // ]
        nonEscapedIdStartChar: /[\$@-Z_a-z\u00AA\u00B5\u00BA\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u1FFF\u2071\u207F\u2090-\u209C\u2102\u2107\u210A-\u2113\u2115\u2119-\u211D\u2124\u2126\u2128\u212A-\u212D\u212F-\u2139\u213C-\u213F\u2145-\u2149\u214E\u2183-\u2184\u2C00-\u2C2E\u2C30-\u2C5E\u2C60-\u2CE4\u2CEB-\u2CEE\u2CF2-\u2CF3\u2D00-\u2D25\u2D27\u2D2D\u2D30-\u2D67\u2D6F\u2D80-\u2D96\u2DA0-\u2DA6\u2DA8-\u2DAE\u2DB0-\u2DB6\u2DB8-\u2DBE\u2DC0-\u2DC6\u2DC8-\u2DCE\u2DD0-\u2DD6\u2DD8-\u2DDE\u2E2F\u3005-\u3006\u3031-\u3035\u303B-\u303C\u3040-\u318F\u31A0-\u31BA\u31F0-\u31FF\u3300-\u337F\u3400-\u4DB5\u4E00-\uA48C\uA4D0-\uA4FD\uA500-\uA60C\uA610-\uA62B\uA640-\uA66E\uA67F-\uA697\uA6A0-\uA6E5\uA717-\uA71F\uA722-\uA788\uA78B-\uA78E\uA790-\uA793\uA7A0-\uA7AA\uA7F8-\uA801\uA803-\uA805\uA807-\uA80A\uA80C-\uA822\uA840-\uA873\uA882-\uA8B3\uA8D0-\uA8D9\uA8F2-\uA8F7\uA8FB\uA900-\uA925\uA930-\uA946\uA960-\uA97C\uA984-\uA9B2\uA9CF-\uA9D9\uAA00-\uAA28\uAA40-\uAA42\uAA44-\uAA4B\uAA50-\uAA59\uAA60-\uAA76\uAA7A\uAA80-\uAAAF\uAAB1\uAAB5-\uAAB6\uAAB9-\uAABD\uAAC0\uAAC2\uAADB-\uAADD\uAAE0-\uAAEA\uAAF2-\uAAF4\uAB01-\uAB06\uAB09-\uAB0E\uAB11-\uAB16\uAB20-\uAB26\uAB28-\uAB2E\uABC0-\uABE2\uABF0-\uABF9\uAC00-\uD7A3\uD7B0-\uD7C6\uD7CB-\uD7FB\uF900-\uFB06\uFB13-\uFB17\uFB1D\uFB1F-\uFB28\uFB2A-\uFB36\uFB38-\uFB3C\uFB3E\uFB40-\uFB41\uFB43-\uFB44\uFB46-\uFBB1\uFBD3-\uFD3D\uFD50-\uFD8F\uFD92-\uFDC7\uFDF0-\uFDFB\uFE70-\uFE74\uFE76-\uFEFC\uFF10-\uFF19\uFF21-\uFF3A\uFF41-\uFF5A\uFF66-\uFFBE\uFFC2-\uFFC7\uFFCA-\uFFCF\uFFD2-\uFFD7\uFFDA-\uFFDC]/,
        // <#ESCAPED_ID_CHAR: "\\" ("-" | "." | ":" | "#")>
        escapedIdChar: /\\[\-\.:#]/,
        // <#ID_START_CHAR: <NON_ESCAPED_ID_START_CHAR>|<ESCAPED_ID_CHAR>>
        idStartChar: /(?:@nonEscapedIdStartChar)|(?:@escapedIdChar)/,
        // <ID: <ID_START_CHAR> (<ID_START_CHAR>|<ASCII_DIGIT>)*>
        id: /(?:@idStartChar)(?:(?:@idStartChar)|(?:@asciiDigit))*/,
        // Certain keywords / operators are allowed to index hashes
        //
        // Expression DotVariable(Expression exp) :
        // {
        // 	Token t;
        // }
        // {
        // 		<DOT>
        // 		(
        // 			t = <ID> | t = <TIMES> | t = <DOUBLE_STAR>
        // 			|
        // 			(
        // 				t = <LESS_THAN>
        // 				|
        // 				t = <LESS_THAN_EQUALS>
        // 				|
        // 				t = <ESCAPED_GT>
        // 				|
        // 				t = <ESCAPED_GTE>
        // 				|
        // 				t = <FALSE>
        // 				|
        // 				t = <TRUE>
        // 				|
        // 				t = <IN>
        // 				|
        // 				t = <AS>
        // 				|
        // 				t = <USING>
        // 			)
        // 			{
        // 				if (!Character.isLetter(t.image.charAt(0))) {
        // 					throw new ParseException(t.image + " is not a valid identifier.", template, t);
        // 				}
        // 			}
        // 		)
        // 		{
        // 			notListLiteral(exp, "hash");
        // 			notStringLiteral(exp, "hash");
        // 			notBooleanLiteral(exp, "hash");
        // 			Dot dot = new Dot(exp, t.image);
        // 			dot.setLocation(template, exp, t);
        // 			return dot;
        // 		}
        // }
        specialHashKeys: /\*\*|\*|false|true|in|as|using/,
        // <DOUBLE_EQUALS : "==">
        // <EQUALS : "=">
        // <NOT_EQUALS : "!=">
        // <PLUS_EQUALS : "+=">
        // <MINUS_EQUALS : "-=">
        // <TIMES_EQUALS : "*=">
        // <DIV_EQUALS : "/=">
        // <MOD_EQUALS : "%=">
        // <PLUS_PLUS : "++">
        // <MINUS_MINUS : "--">
        // <LESS_THAN_EQUALS : "lte" | "\\lte" | "<=" | "&lt;=">
        // <LESS_THAN : "lt" | "\\lt" | "<" | "&lt;">
        // <ESCAPED_GTE : "gte" | "\\gte" | "&gt;=">
        // <ESCAPED_GT: "gt" | "\\gt" |  "&gt;">
        // <DOUBLE_STAR : "**">
        // <PLUS : "+">
        // <MINUS : "-">
        // <TIMES : "*">
        // <PERCENT : "%">
        // <AND : "&" | "&&" | "&amp;&amp;" | "\\and" >
        // <OR : "|" | "||">
        // <EXCLAM : "!">
        // <COMMA : ",">
        // <SEMICOLON : ";">
        // <COLON : ":">
        // <ELLIPSIS : "...">
        // <DOT_DOT_ASTERISK : "..*" >
        // <DOT_DOT_LESS : "..<" | "..!" >
        // <DOT_DOT : "..">
        // <EXISTS : "??">
        // <BUILT_IN : "?">
        // <LAMBDA_ARROW : "->" | "-&gt;">
        namedSymbols: /&lt;=|&gt;=|\\lte|\\lt|&lt;|\\gte|\\gt|&gt;|&amp;&amp;|\\and|-&gt;|->|==|!=|\+=|-=|\*=|\/=|%=|\+\+|--|<=|&&|\|\||:|\.\.\.|\.\.\*|\.\.<|\.\.!|\?\?|=|<|\+|-|\*|\/|%|\||\.\.|\?|!|&|\.|,|;/,
        arrows: [
            "->",
            "-&gt;"
        ],
        delimiters: [
            ";",
            ":",
            ",",
            "."
        ],
        stringOperators: [
            "lte",
            "lt",
            "gte",
            "gt"
        ],
        noParseTags: [
            "noparse",
            "noParse",
            "comment"
        ],
        tokenizer: {
            // Parser states
            // Plain text
            [s("default__id__")]: [
                {
                    include: s("@directive_token__id__")
                },
                {
                    include: s("@interpolation_and_text_token__id__")
                }
            ],
            // A FreeMarker expression inside a directive, e.g. <#if 2<3>
            [s("fmExpression__id__.directive")]: [
                {
                    include: s("@blank_and_expression_comment_token__id__")
                },
                {
                    include: s("@directive_end_token__id__")
                },
                {
                    include: s("@expression_token__id__")
                }
            ],
            // A FreeMarker expression inside an interpolation, e.g. ${2+3}
            [s("fmExpression__id__.interpolation")]: [
                {
                    include: s("@blank_and_expression_comment_token__id__")
                },
                {
                    include: s("@expression_token__id__")
                },
                {
                    include: s("@greater_operators_token__id__")
                }
            ],
            // In an expression and inside a not-yet closed parenthesis / bracket
            [s("inParen__id__.plain")]: [
                {
                    include: s("@blank_and_expression_comment_token__id__")
                },
                {
                    include: s("@directive_end_token__id__")
                },
                {
                    include: s("@expression_token__id__")
                }
            ],
            [s("inParen__id__.gt")]: [
                {
                    include: s("@blank_and_expression_comment_token__id__")
                },
                {
                    include: s("@expression_token__id__")
                },
                {
                    include: s("@greater_operators_token__id__")
                }
            ],
            // Expression for the unified call, e.g. <@createMacro() ... >
            [s("noSpaceExpression__id__")]: [
                {
                    include: s("@no_space_expression_end_token__id__")
                },
                {
                    include: s("@directive_end_token__id__")
                },
                {
                    include: s("@expression_token__id__")
                }
            ],
            // For the function of a unified call. Special case for when the
            // expression is a simple identifier.
            // <@join [1,2] ",">
            // <@null!join [1,2] ",">
            [s("unifiedCall__id__")]: [
                {
                    include: s("@unified_call_token__id__")
                }
            ],
            // For singly and doubly quoted string (that may contain interpolations)
            [s("singleString__id__")]: [
                {
                    include: s("@string_single_token__id__")
                }
            ],
            [s("doubleString__id__")]: [
                {
                    include: s("@string_double_token__id__")
                }
            ],
            // For singly and doubly quoted string (that may not contain interpolations)
            [s("rawSingleString__id__")]: [
                {
                    include: s("@string_single_raw_token__id__")
                }
            ],
            [s("rawDoubleString__id__")]: [
                {
                    include: s("@string_double_raw_token__id__")
                }
            ],
            // For a comment in an expression
            // ${ 1 + <#-- comment --> 2}
            [s("expressionComment__id__")]: [
                {
                    include: s("@expression_comment_token__id__")
                }
            ],
            // For <#noparse> ... </#noparse>
            // For <#noParse> ... </#noParse>
            // For <#comment> ... </#comment>
            [s("noParse__id__")]: [
                {
                    include: s("@no_parse_token__id__")
                }
            ],
            // For <#-- ... -->
            [s("terseComment__id__")]: [
                {
                    include: s("@terse_comment_token__id__")
                }
            ],
            // Common rules
            [s("directive_token__id__")]: [
                // <ATTEMPT : <START_TAG> "attempt" <CLOSE_TAG1>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <RECOVER : <START_TAG> "recover" <CLOSE_TAG1>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <SEP : <START_TAG> "sep" <CLOSE_TAG1>>
                // <AUTOESC : <START_TAG> "auto" ("e"|"E") "sc" <CLOSE_TAG1>> {
                //     handleTagSyntaxAndSwitch(matchedToken, getTagNamingConvention(matchedToken, 4), DEFAULT);
                // }
                // <NOAUTOESC : <START_TAG> "no" ("autoe"|"AutoE") "sc" <CLOSE_TAG1>> {
                //     handleTagSyntaxAndSwitch(matchedToken, getTagNamingConvention(matchedToken, 2), DEFAULT);
                // }
                // <COMPRESS : <START_TAG> "compress" <CLOSE_TAG1>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <DEFAUL : <START_TAG> "default" <CLOSE_TAG1>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <NOESCAPE : <START_TAG> "no" ("e" | "E") "scape" <CLOSE_TAG1>> {
                //     handleTagSyntaxAndSwitch(matchedToken, getTagNamingConvention(matchedToken, 2), DEFAULT);
                // }
                //
                // <COMMENT : <START_TAG> "comment" <CLOSE_TAG1>> {
                //     handleTagSyntaxAndSwitch(matchedToken, NO_PARSE); noparseTag = "comment";
                // }
                // <NOPARSE: <START_TAG> "no" ("p" | "P") "arse" <CLOSE_TAG1>> {
                //     int tagNamingConvention = getTagNamingConvention(matchedToken, 2);
                //     handleTagSyntaxAndSwitch(matchedToken, tagNamingConvention, NO_PARSE);
                //     noparseTag = tagNamingConvention == Configuration.CAMEL_CASE_NAMING_CONVENTION ? "noParse" : "noparse";
                // }
                [
                    r(/(?:@startTag__id__)(@directiveStartCloseTag1)(?:@closeTag1__id__)/),
                    ts.id === "auto" ? {
                        cases: {
                            "$1==<": {
                                token: "@rematch",
                                switchTo: `@default_angle_${is.id}`
                            },
                            "$1==[": {
                                token: "@rematch",
                                switchTo: `@default_bracket_${is.id}`
                            }
                        }
                    } : [
                        {
                            token: "@brackets.directive"
                        },
                        {
                            token: "delimiter.directive"
                        },
                        {
                            cases: {
                                "@noParseTags": {
                                    token: "tag",
                                    next: s("@noParse__id__.$3")
                                },
                                "@default": {
                                    token: "tag"
                                }
                            }
                        },
                        {
                            token: "delimiter.directive"
                        },
                        {
                            token: "@brackets.directive"
                        }
                    ]
                ],
                // <ELSE : <START_TAG> "else" <CLOSE_TAG2>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <BREAK : <START_TAG> "break" <CLOSE_TAG2>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <CONTINUE : <START_TAG> "continue" <CLOSE_TAG2>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <SIMPLE_RETURN : <START_TAG> "return" <CLOSE_TAG2>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <HALT : <START_TAG> "stop" <CLOSE_TAG2>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <FLUSH : <START_TAG> "flush" <CLOSE_TAG2>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <TRIM : <START_TAG> "t" <CLOSE_TAG2>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <LTRIM : <START_TAG> "lt" <CLOSE_TAG2>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <RTRIM : <START_TAG> "rt" <CLOSE_TAG2>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <NOTRIM : <START_TAG> "nt" <CLOSE_TAG2>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <SIMPLE_NESTED : <START_TAG> "nested" <CLOSE_TAG2>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <SIMPLE_RECURSE : <START_TAG> "recurse" <CLOSE_TAG2>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <FALLBACK : <START_TAG> "fallback" <CLOSE_TAG2>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <TRIVIAL_FTL_HEADER : ("<#ftl" | "[#ftl") ("/")? (">" | "]")> { ftlHeader(matchedToken); }
                [
                    r(/(?:@startTag__id__)(@directiveStartCloseTag2)(?:@closeTag2__id__)/),
                    ts.id === "auto" ? {
                        cases: {
                            "$1==<": {
                                token: "@rematch",
                                switchTo: `@default_angle_${is.id}`
                            },
                            "$1==[": {
                                token: "@rematch",
                                switchTo: `@default_bracket_${is.id}`
                            }
                        }
                    } : [
                        {
                            token: "@brackets.directive"
                        },
                        {
                            token: "delimiter.directive"
                        },
                        {
                            token: "tag"
                        },
                        {
                            token: "delimiter.directive"
                        },
                        {
                            token: "@brackets.directive"
                        }
                    ]
                ],
                // <IF : <START_TAG> "if" <BLANK>> { handleTagSyntaxAndSwitch(matchedToken, FM_EXPRESSION); }
                // <ELSE_IF : <START_TAG> "else" ("i" | "I") "f" <BLANK>> {
                // 	handleTagSyntaxAndSwitch(matchedToken, getTagNamingConvention(matchedToken, 4), FM_EXPRESSION);
                // }
                // <LIST : <START_TAG> "list" <BLANK>> { handleTagSyntaxAndSwitch(matchedToken, FM_EXPRESSION); }
                // <FOREACH : <START_TAG> "for" ("e" | "E") "ach" <BLANK>> {
                //    handleTagSyntaxAndSwitch(matchedToken, getTagNamingConvention(matchedToken, 3), FM_EXPRESSION);
                // }
                // <SWITCH : <START_TAG> "switch" <BLANK>> { handleTagSyntaxAndSwitch(matchedToken, FM_EXPRESSION); }
                // <CASE : <START_TAG> "case" <BLANK>> { handleTagSyntaxAndSwitch(matchedToken, FM_EXPRESSION); }
                // <ASSIGN : <START_TAG> "assign" <BLANK>> { handleTagSyntaxAndSwitch(matchedToken, FM_EXPRESSION); }
                // <GLOBALASSIGN : <START_TAG> "global" <BLANK>> { handleTagSyntaxAndSwitch(matchedToken, FM_EXPRESSION); }
                // <LOCALASSIGN : <START_TAG> "local" <BLANK>> { handleTagSyntaxAndSwitch(matchedToken, FM_EXPRESSION); }
                // <_INCLUDE : <START_TAG> "include" <BLANK>> { handleTagSyntaxAndSwitch(matchedToken, FM_EXPRESSION); }
                // <IMPORT : <START_TAG> "import" <BLANK>> { handleTagSyntaxAndSwitch(matchedToken, FM_EXPRESSION); }
                // <FUNCTION : <START_TAG> "function" <BLANK>> { handleTagSyntaxAndSwitch(matchedToken, FM_EXPRESSION); }
                // <MACRO : <START_TAG> "macro" <BLANK>> { handleTagSyntaxAndSwitch(matchedToken, FM_EXPRESSION); }
                // <TRANSFORM : <START_TAG> "transform" <BLANK>> { handleTagSyntaxAndSwitch(matchedToken, FM_EXPRESSION); }
                // <VISIT : <START_TAG> "visit" <BLANK>> { handleTagSyntaxAndSwitch(matchedToken, FM_EXPRESSION); }
                // <STOP : <START_TAG> "stop" <BLANK>> { handleTagSyntaxAndSwitch(matchedToken, FM_EXPRESSION); }
                // <RETURN : <START_TAG> "return" <BLANK>> { handleTagSyntaxAndSwitch(matchedToken, FM_EXPRESSION); }
                // <CALL : <START_TAG> "call" <BLANK>> { handleTagSyntaxAndSwitch(matchedToken, FM_EXPRESSION); }
                // <SETTING : <START_TAG> "setting" <BLANK>> { handleTagSyntaxAndSwitch(matchedToken, FM_EXPRESSION); }
                // <OUTPUTFORMAT : <START_TAG> "output" ("f"|"F") "ormat" <BLANK>> {
                //    handleTagSyntaxAndSwitch(matchedToken, getTagNamingConvention(matchedToken, 6), FM_EXPRESSION);
                // }
                // <NESTED : <START_TAG> "nested" <BLANK>> { handleTagSyntaxAndSwitch(matchedToken, FM_EXPRESSION); }
                // <RECURSE : <START_TAG> "recurse" <BLANK>> { handleTagSyntaxAndSwitch(matchedToken, FM_EXPRESSION); }
                // <ESCAPE : <START_TAG> "escape" <BLANK>> { handleTagSyntaxAndSwitch(matchedToken, FM_EXPRESSION); }
                //
                // Note: FreeMarker grammar appears to treat the FTL header as a special case,
                // in order to remove new lines after the header (?), but since we only need
                // to tokenize for highlighting, we can include this directive here.
                // <FTL_HEADER : ("<#ftl" | "[#ftl") <BLANK>> { ftlHeader(matchedToken); }
                //
                // Note: FreeMarker grammar appears to treat the items directive as a special case for
                // the AST parsing process, but since we only need to tokenize, we can include this
                // directive here.
                // <ITEMS : <START_TAG> "items" (<BLANK>)+ <AS> <BLANK>> { handleTagSyntaxAndSwitch(matchedToken, FM_EXPRESSION); }
                [
                    r(/(?:@startTag__id__)(@directiveStartBlank)(@blank)/),
                    ts.id === "auto" ? {
                        cases: {
                            "$1==<": {
                                token: "@rematch",
                                switchTo: `@default_angle_${is.id}`
                            },
                            "$1==[": {
                                token: "@rematch",
                                switchTo: `@default_bracket_${is.id}`
                            }
                        }
                    } : [
                        {
                            token: "@brackets.directive"
                        },
                        {
                            token: "delimiter.directive"
                        },
                        {
                            token: "tag"
                        },
                        {
                            token: "",
                            next: s("@fmExpression__id__.directive")
                        }
                    ]
                ],
                // <END_IF : <END_TAG> "if" <CLOSE_TAG1>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <END_LIST : <END_TAG> "list" <CLOSE_TAG1>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <END_SEP : <END_TAG> "sep" <CLOSE_TAG1>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <END_RECOVER : <END_TAG> "recover" <CLOSE_TAG1>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <END_ATTEMPT : <END_TAG> "attempt" <CLOSE_TAG1>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <END_FOREACH : <END_TAG> "for" ("e" | "E") "ach" <CLOSE_TAG1>> {
                //     handleTagSyntaxAndSwitch(matchedToken, getTagNamingConvention(matchedToken, 3), DEFAULT);
                // }
                // <END_LOCAL : <END_TAG> "local" <CLOSE_TAG1>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <END_GLOBAL : <END_TAG> "global" <CLOSE_TAG1>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <END_ASSIGN : <END_TAG> "assign" <CLOSE_TAG1>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <END_FUNCTION : <END_TAG> "function" <CLOSE_TAG1>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <END_MACRO : <END_TAG> "macro" <CLOSE_TAG1>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <END_OUTPUTFORMAT : <END_TAG> "output" ("f" | "F") "ormat" <CLOSE_TAG1>> {
                //     handleTagSyntaxAndSwitch(matchedToken, getTagNamingConvention(matchedToken, 6), DEFAULT);
                // }
                // <END_AUTOESC : <END_TAG> "auto" ("e" | "E") "sc" <CLOSE_TAG1>> {
                //     handleTagSyntaxAndSwitch(matchedToken, getTagNamingConvention(matchedToken, 4), DEFAULT);
                // }
                // <END_NOAUTOESC : <END_TAG> "no" ("autoe"|"AutoE") "sc" <CLOSE_TAG1>> {
                //   handleTagSyntaxAndSwitch(matchedToken, getTagNamingConvention(matchedToken, 2), DEFAULT);
                // }
                // <END_COMPRESS : <END_TAG> "compress" <CLOSE_TAG1>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <END_TRANSFORM : <END_TAG> "transform" <CLOSE_TAG1>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <END_SWITCH : <END_TAG> "switch" <CLOSE_TAG1>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <END_ESCAPE : <END_TAG> "escape" <CLOSE_TAG1>> { handleTagSyntaxAndSwitch(matchedToken, DEFAULT); }
                // <END_NOESCAPE : <END_TAG> "no" ("e" | "E") "scape" <CLOSE_TAG1>> {
                //     handleTagSyntaxAndSwitch(matchedToken, getTagNamingConvention(matchedToken, 2), DEFAULT);
                // }
                [
                    r(/(?:@endTag__id__)(@directiveEndCloseTag1)(?:@closeTag1__id__)/),
                    ts.id === "auto" ? {
                        cases: {
                            "$1==<": {
                                token: "@rematch",
                                switchTo: `@default_angle_${is.id}`
                            },
                            "$1==[": {
                                token: "@rematch",
                                switchTo: `@default_bracket_${is.id}`
                            }
                        }
                    } : [
                        {
                            token: "@brackets.directive"
                        },
                        {
                            token: "delimiter.directive"
                        },
                        {
                            token: "tag"
                        },
                        {
                            token: "delimiter.directive"
                        },
                        {
                            token: "@brackets.directive"
                        }
                    ]
                ],
                // <UNIFIED_CALL : "<@" | "[@" > { unifiedCall(matchedToken); }
                [
                    r(/(@open__id__)(@)/),
                    ts.id === "auto" ? {
                        cases: {
                            "$1==<": {
                                token: "@rematch",
                                switchTo: `@default_angle_${is.id}`
                            },
                            "$1==[": {
                                token: "@rematch",
                                switchTo: `@default_bracket_${is.id}`
                            }
                        }
                    } : [
                        {
                            token: "@brackets.directive"
                        },
                        {
                            token: "delimiter.directive",
                            next: s("@unifiedCall__id__")
                        }
                    ]
                ],
                // <UNIFIED_CALL_END : ("<" | "[") "/@" ((<ID>) ("."<ID>)*)? <CLOSE_TAG1>> { unifiedCallEnd(matchedToken); }
                [
                    r(/(@open__id__)(\/@)((?:(?:@id)(?:\.(?:@id))*)?)(?:@closeTag1__id__)/),
                    [
                        {
                            token: "@brackets.directive"
                        },
                        {
                            token: "delimiter.directive"
                        },
                        {
                            token: "tag"
                        },
                        {
                            token: "delimiter.directive"
                        },
                        {
                            token: "@brackets.directive"
                        }
                    ]
                ],
                // <TERSE_COMMENT : ("<" | "[") "#--" > { noparseTag = "-->"; handleTagSyntaxAndSwitch(matchedToken, NO_PARSE); }
                [
                    r(/(@open__id__)#--/),
                    ts.id === "auto" ? {
                        cases: {
                            "$1==<": {
                                token: "@rematch",
                                switchTo: `@default_angle_${is.id}`
                            },
                            "$1==[": {
                                token: "@rematch",
                                switchTo: `@default_bracket_${is.id}`
                            }
                        }
                    } : {
                        token: "comment",
                        next: s("@terseComment__id__")
                    }
                ],
                // <UNKNOWN_DIRECTIVE : ("[#" | "[/#" | "<#" | "</#") (["a"-"z", "A"-"Z", "_"])+>
                [
                    r(/(?:@startOrEndTag__id__)([a-zA-Z_]+)/),
                    ts.id === "auto" ? {
                        cases: {
                            "$1==<": {
                                token: "@rematch",
                                switchTo: `@default_angle_${is.id}`
                            },
                            "$1==[": {
                                token: "@rematch",
                                switchTo: `@default_bracket_${is.id}`
                            }
                        }
                    } : [
                        {
                            token: "@brackets.directive"
                        },
                        {
                            token: "delimiter.directive"
                        },
                        {
                            token: "tag.invalid",
                            next: s("@fmExpression__id__.directive")
                        }
                    ]
                ]
            ],
            // <DEFAULT, NO_DIRECTIVE> TOKEN :
            [s("interpolation_and_text_token__id__")]: [
                // <DOLLAR_INTERPOLATION_OPENING : "${"> { startInterpolation(matchedToken); }
                // <SQUARE_BRACKET_INTERPOLATION_OPENING : "[="> { startInterpolation(matchedToken); }
                [
                    r(/(@iOpen1__id__)(@iOpen2__id__)/),
                    [
                        {
                            token: is.id === "bracket" ? "@brackets.interpolation" : "delimiter.interpolation"
                        },
                        {
                            token: is.id === "bracket" ? "delimiter.interpolation" : "@brackets.interpolation",
                            next: s("@fmExpression__id__.interpolation")
                        }
                    ]
                ],
                // <STATIC_TEXT_FALSE_ALARM : "$" | "#" | "<" | "[" | "{"> // to handle a lone dollar sign or "<" or "# or <@ with whitespace after"
                // <STATIC_TEXT_WS : ("\n" | "\r" | "\t" | " ")+>
                // <STATIC_TEXT_NON_WS : (~["$", "<", "#", "[", "{", "\n", "\r", "\t", " "])+>
                [
                    /[\$#<\[\{]|(?:@blank)+|[^\$<#\[\{\n\r\t ]+/,
                    {
                        token: "source"
                    }
                ]
            ],
            // <STRING_LITERAL :
            // 	(
            // 		"\""
            // 		((~["\"", "\\"]) | <ESCAPED_CHAR>)*
            // 		"\""
            // 	)
            // 	|
            // 	(
            // 		"'"
            // 		((~["'", "\\"]) | <ESCAPED_CHAR>)*
            // 		"'"
            // 	)
            // >
            [s("string_single_token__id__")]: [
                [
                    /[^'\\]/,
                    {
                        token: "string"
                    }
                ],
                [
                    /@escapedChar/,
                    {
                        token: "string.escape"
                    }
                ],
                [
                    /'/,
                    {
                        token: "string",
                        next: "@pop"
                    }
                ]
            ],
            [s("string_double_token__id__")]: [
                [
                    /[^"\\]/,
                    {
                        token: "string"
                    }
                ],
                [
                    /@escapedChar/,
                    {
                        token: "string.escape"
                    }
                ],
                [
                    /"/,
                    {
                        token: "string",
                        next: "@pop"
                    }
                ]
            ],
            // <RAW_STRING : "r" (("\"" (~["\""])* "\"") | ("'" (~["'"])* "'"))>
            [s("string_single_raw_token__id__")]: [
                [
                    /[^']+/,
                    {
                        token: "string.raw"
                    }
                ],
                [
                    /'/,
                    {
                        token: "string.raw",
                        next: "@pop"
                    }
                ]
            ],
            [s("string_double_raw_token__id__")]: [
                [
                    /[^"]+/,
                    {
                        token: "string.raw"
                    }
                ],
                [
                    /"/,
                    {
                        token: "string.raw",
                        next: "@pop"
                    }
                ]
            ],
            // <FM_EXPRESSION, IN_PAREN, NO_SPACE_EXPRESSION, NAMED_PARAMETER_EXPRESSION> TOKEN :
            [s("expression_token__id__")]: [
                // Strings
                [
                    /(r?)(['"])/,
                    {
                        cases: {
                            "r'": [
                                {
                                    token: "keyword"
                                },
                                {
                                    token: "string.raw",
                                    next: s("@rawSingleString__id__")
                                }
                            ],
                            'r"': [
                                {
                                    token: "keyword"
                                },
                                {
                                    token: "string.raw",
                                    next: s("@rawDoubleString__id__")
                                }
                            ],
                            "'": [
                                {
                                    token: "source"
                                },
                                {
                                    token: "string",
                                    next: s("@singleString__id__")
                                }
                            ],
                            '"': [
                                {
                                    token: "source"
                                },
                                {
                                    token: "string",
                                    next: s("@doubleString__id__")
                                }
                            ]
                        }
                    }
                ],
                // Numbers
                // <INTEGER : (["0"-"9"])+>
                // <DECIMAL : <INTEGER> "." <INTEGER>>
                [
                    /(?:@integer)(?:\.(?:@integer))?/,
                    {
                        cases: {
                            "(?:@integer)": {
                                token: "number"
                            },
                            "@default": {
                                token: "number.float"
                            }
                        }
                    }
                ],
                // Special hash keys that must not be treated as identifiers
                // after a period, e.g. a.** is accessing the key "**" of a
                [
                    /(\.)(@blank*)(@specialHashKeys)/,
                    [
                        {
                            token: "delimiter"
                        },
                        {
                            token: ""
                        },
                        {
                            token: "identifier"
                        }
                    ]
                ],
                // Symbols / operators
                [
                    /(?:@namedSymbols)/,
                    {
                        cases: {
                            "@arrows": {
                                token: "meta.arrow"
                            },
                            "@delimiters": {
                                token: "delimiter"
                            },
                            "@default": {
                                token: "operators"
                            }
                        }
                    }
                ],
                // Identifiers
                [
                    /@id/,
                    {
                        cases: {
                            "@keywords": {
                                token: "keyword.$0"
                            },
                            "@stringOperators": {
                                token: "operators"
                            },
                            "@default": {
                                token: "identifier"
                            }
                        }
                    }
                ],
                // <OPEN_BRACKET : "[">
                // <CLOSE_BRACKET : "]">
                // <OPEN_PAREN : "(">
                // <CLOSE_PAREN : ")">
                // <OPENING_CURLY_BRACKET : "{">
                // <CLOSING_CURLY_BRACKET : "}">
                [
                    /[\[\]\(\)\{\}]/,
                    {
                        cases: {
                            "\\[": {
                                cases: {
                                    "$S2==gt": {
                                        token: "@brackets",
                                        next: s("@inParen__id__.gt")
                                    },
                                    "@default": {
                                        token: "@brackets",
                                        next: s("@inParen__id__.plain")
                                    }
                                }
                            },
                            "\\]": {
                                cases: {
                                    ...is.id === "bracket" ? {
                                        "$S2==interpolation": {
                                            token: "@brackets.interpolation",
                                            next: "@popall"
                                        }
                                    } : {},
                                    // This cannot happen while in auto mode, since this applies only to an
                                    // fmExpression inside a directive. But once we encounter the start of a
                                    // directive, we can establish the tag syntax mode.
                                    ...ts.id === "bracket" ? {
                                        "$S2==directive": {
                                            token: "@brackets.directive",
                                            next: "@popall"
                                        }
                                    } : {},
                                    // Ignore mismatched paren
                                    [s("$S1==inParen__id__")]: {
                                        token: "@brackets",
                                        next: "@pop"
                                    },
                                    "@default": {
                                        token: "@brackets"
                                    }
                                }
                            },
                            "\\(": {
                                token: "@brackets",
                                next: s("@inParen__id__.gt")
                            },
                            "\\)": {
                                cases: {
                                    [s("$S1==inParen__id__")]: {
                                        token: "@brackets",
                                        next: "@pop"
                                    },
                                    "@default": {
                                        token: "@brackets"
                                    }
                                }
                            },
                            "\\{": {
                                cases: {
                                    "$S2==gt": {
                                        token: "@brackets",
                                        next: s("@inParen__id__.gt")
                                    },
                                    "@default": {
                                        token: "@brackets",
                                        next: s("@inParen__id__.plain")
                                    }
                                }
                            },
                            "\\}": {
                                cases: {
                                    ...is.id === "bracket" ? {} : {
                                        "$S2==interpolation": {
                                            token: "@brackets.interpolation",
                                            next: "@popall"
                                        }
                                    },
                                    // Ignore mismatched paren
                                    [s("$S1==inParen__id__")]: {
                                        token: "@brackets",
                                        next: "@pop"
                                    },
                                    "@default": {
                                        token: "@brackets"
                                    }
                                }
                            }
                        }
                    }
                ],
                // <OPEN_MISPLACED_INTERPOLATION : "${" | "#{" | "[=">
                [
                    /\$\{/,
                    {
                        token: "delimiter.invalid"
                    }
                ]
            ],
            // <FM_EXPRESSION, IN_PAREN, NAMED_PARAMETER_EXPRESSION> SKIP :
            [s("blank_and_expression_comment_token__id__")]: [
                // < ( " " | "\t" | "\n" | "\r" )+ >
                [
                    /(?:@blank)+/,
                    {
                        token: ""
                    }
                ],
                // < ("<" | "[") ("#" | "!") "--"> : EXPRESSION_COMMENT
                [
                    /[<\[][#!]--/,
                    {
                        token: "comment",
                        next: s("@expressionComment__id__")
                    }
                ]
            ],
            // <FM_EXPRESSION, NO_SPACE_EXPRESSION, NAMED_PARAMETER_EXPRESSION> TOKEN :
            [s("directive_end_token__id__")]: [
                // <DIRECTIVE_END : ">">
                // {
                //     if (inFTLHeader) {
                //         eatNewline();
                //         inFTLHeader = false;
                //     }
                //     if (squBracTagSyntax || postInterpolationLexState != -1 /* We are in an interpolation */) {
                //         matchedToken.kind = NATURAL_GT;
                //     } else {
                //         SwitchTo(DEFAULT);
                //     }
                // }
                // This cannot happen while in auto mode, since this applies only to an
                // fmExpression inside a directive. But once we encounter the start of a
                // directive, we can establish the tag syntax mode.
                [
                    />/,
                    ts.id === "bracket" ? {
                        token: "operators"
                    } : {
                        token: "@brackets.directive",
                        next: "@popall"
                    }
                ],
                // <EMPTY_DIRECTIVE_END : "/>" | "/]">
                // It is a syntax error to end a tag with the wrong close token
                // Let's indicate that to the user by not closing the tag
                [
                    r(/(\/)(@close__id__)/),
                    [
                        {
                            token: "delimiter.directive"
                        },
                        {
                            token: "@brackets.directive",
                            next: "@popall"
                        }
                    ]
                ]
            ],
            // <IN_PAREN> TOKEN :
            [s("greater_operators_token__id__")]: [
                // <NATURAL_GT : ">">
                [
                    />/,
                    {
                        token: "operators"
                    }
                ],
                // <NATURAL_GTE : ">=">
                [
                    />=/,
                    {
                        token: "operators"
                    }
                ]
            ],
            // <NO_SPACE_EXPRESSION> TOKEN :
            [s("no_space_expression_end_token__id__")]: [
                // <TERMINATING_WHITESPACE :  (["\n", "\r", "\t", " "])+> : FM_EXPRESSION
                [
                    /(?:@blank)+/,
                    {
                        token: "",
                        switchTo: s("@fmExpression__id__.directive")
                    }
                ]
            ],
            [s("unified_call_token__id__")]: [
                // Special case for a call where the expression is just an ID
                // <UNIFIED_CALL> <ID> <BLANK>+
                [
                    /(@id)((?:@blank)+)/,
                    [
                        {
                            token: "tag"
                        },
                        {
                            token: "",
                            next: s("@fmExpression__id__.directive")
                        }
                    ]
                ],
                [
                    r(/(@id)(\/?)(@close__id__)/),
                    [
                        {
                            token: "tag"
                        },
                        {
                            token: "delimiter.directive"
                        },
                        {
                            token: "@brackets.directive",
                            next: "@popall"
                        }
                    ]
                ],
                [
                    /./,
                    {
                        token: "@rematch",
                        next: s("@noSpaceExpression__id__")
                    }
                ]
            ],
            // <NO_PARSE> TOKEN :
            [s("no_parse_token__id__")]: [
                // <MAYBE_END :
                // 	 ("<" | "[")
                // 	 "/"
                // 	 ("#")?
                // 	 (["a"-"z", "A"-"Z"])+
                // 	 ( " " | "\t" | "\n" | "\r" )*
                // 	 (">" | "]")
                // >
                [
                    r(/(@open__id__)(\/#?)([a-zA-Z]+)((?:@blank)*)(@close__id__)/),
                    {
                        cases: {
                            "$S2==$3": [
                                {
                                    token: "@brackets.directive"
                                },
                                {
                                    token: "delimiter.directive"
                                },
                                {
                                    token: "tag"
                                },
                                {
                                    token: ""
                                },
                                {
                                    token: "@brackets.directive",
                                    next: "@popall"
                                }
                            ],
                            "$S2==comment": [
                                {
                                    token: "comment"
                                },
                                {
                                    token: "comment"
                                },
                                {
                                    token: "comment"
                                },
                                {
                                    token: "comment"
                                },
                                {
                                    token: "comment"
                                }
                            ],
                            "@default": [
                                {
                                    token: "source"
                                },
                                {
                                    token: "source"
                                },
                                {
                                    token: "source"
                                },
                                {
                                    token: "source"
                                },
                                {
                                    token: "source"
                                }
                            ]
                        }
                    }
                ],
                // <KEEP_GOING : (~["<", "[", "-"])+>
                // <LONE_LESS_THAN_OR_DASH : ["<", "[", "-"]>
                [
                    /[^<\[\-]+|[<\[\-]/,
                    {
                        cases: {
                            "$S2==comment": {
                                token: "comment"
                            },
                            "@default": {
                                token: "source"
                            }
                        }
                    }
                ]
            ],
            // <EXPRESSION_COMMENT> SKIP:
            [s("expression_comment_token__id__")]: [
                // < "-->" | "--]">
                [
                    /--[>\]]/,
                    {
                        token: "comment",
                        next: "@pop"
                    }
                ],
                // < (~["-", ">", "]"])+ >
                // < ">">
                // < "]">
                // < "-">
                [
                    /[^\->\]]+|[>\]\-]/,
                    {
                        token: "comment"
                    }
                ]
            ],
            [s("terse_comment_token__id__")]: [
                //  <TERSE_COMMENT_END : "-->" | "--]">
                [
                    r(/--(?:@close__id__)/),
                    {
                        token: "comment",
                        next: "@popall"
                    }
                ],
                // <KEEP_GOING : (~["<", "[", "-"])+>
                // <LONE_LESS_THAN_OR_DASH : ["<", "[", "-"]>
                [
                    /[^<\[\-]+|[<\[\-]/,
                    {
                        token: "comment"
                    }
                ]
            ]
        }
    };
}
function createMonarchLanguageAuto(is) {
    const angle = createMonarchLanguage(TagSyntaxAngle, is);
    const bracket = createMonarchLanguage(TagSyntaxBracket, is);
    const auto = createMonarchLanguage(TagSyntaxAuto, is);
    return {
        // Angle and bracket syntax mode
        // We switch to one of these once we have determined the mode
        ...angle,
        ...bracket,
        ...auto,
        // Settings
        unicode: true,
        includeLF: false,
        start: `default_auto_${is.id}`,
        ignoreCase: false,
        defaultToken: "invalid",
        tokenPostfix: `.freemarker2`,
        brackets: [
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
        tokenizer: {
            ...angle.tokenizer,
            ...bracket.tokenizer,
            ...auto.tokenizer
        }
    };
}
var TagAngleInterpolationDollar = {
    conf: createLangConfiguration(TagSyntaxAngle),
    language: createMonarchLanguage(TagSyntaxAngle, InterpolationSyntaxDollar)
};
var TagBracketInterpolationDollar = {
    conf: createLangConfiguration(TagSyntaxBracket),
    language: createMonarchLanguage(TagSyntaxBracket, InterpolationSyntaxDollar)
};
var TagAngleInterpolationBracket = {
    conf: createLangConfiguration(TagSyntaxAngle),
    language: createMonarchLanguage(TagSyntaxAngle, InterpolationSyntaxBracket)
};
var TagBracketInterpolationBracket = {
    conf: createLangConfiguration(TagSyntaxBracket),
    language: createMonarchLanguage(TagSyntaxBracket, InterpolationSyntaxBracket)
};
var TagAutoInterpolationDollar = {
    conf: createLangConfigurationAuto(),
    language: createMonarchLanguageAuto(InterpolationSyntaxDollar)
};
var TagAutoInterpolationBracket = {
    conf: createLangConfigurationAuto(),
    language: createMonarchLanguageAuto(InterpolationSyntaxBracket)
};

},{"../../editor/editor.api.js":"i7fbg","@parcel/transformer-js/src/esmodule-helpers.js":"jnFvT"}]},["gaUzL"], null, "parcelRequire8661", {})

//# sourceMappingURL=freemarker2.82877aae.js.map
