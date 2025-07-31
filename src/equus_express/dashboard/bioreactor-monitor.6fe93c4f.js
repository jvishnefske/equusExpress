var e=globalThis.parcelRequire8661;(0,e.register)("8Tk2M",function(t,a){Object.defineProperty(t.exports,"setupBioreactorMonitor",{get:()=>o,set:void 0,enumerable:!0,configurable:!0});var n=e("bgI6x");function o(e,t){t.innerHTML=`
    <div class="monitor-container">
      <h2>Bioreactor Monitor</h2>
      <div class="status-bar">
        NATS Connection: <span id="nats-connection-status">Connecting...</span>
      </div>

      <div id="bioreactor-content">
        <h3>Live Data for Batch: <span id="batch-id">Waiting...</span></h3>
        <div class="data-grid">
          <div class="data-item">
            <span class="label">State</span>
            <span class="value" id="state-value">N/A</span>
          </div>
          <div class="data-item">
            <span class="label">Temperature</span>
            <span class="value" id="temperature-value">N/A</span>
          </div>
          <div class="data-item">
            <span class="label">pH</span>
            <span class="value" id="ph-value">N/A</span>
          </div>
          <div class="data-item">
            <span class="label">CarbonDioxide PPM</span>
            <span class="value" id="do-value">N/A</span>
          </div>
        </div>

        <div class="controls">
          <button id="hold-button">Hold Process</button>
          <button id="restart-button">Restart Process</button>
        </div>
      </div>

      <p id="disconnected-message" class="message" style="display: none;">Connecting to NATS server...</p>
    </div>
  `;let a=t.querySelector("#nats-connection-status"),o=t.querySelector("#batch-id"),s=t.querySelector("#state-value"),r=t.querySelector("#temperature-value"),i=t.querySelector("#ph-value"),c=t.querySelector("#do-value"),l=t.querySelector("#hold-button"),d=t.querySelector("#restart-button"),u=t.querySelector("#bioreactor-content"),p=t.querySelector("#disconnected-message"),b=document.createElement("style");b.textContent=`
    .monitor-container { border: 1px solid #ccc; padding: 16px; border-radius: 8px; font-family: sans-serif; }
    .status-bar { margin-bottom: 16px; font-weight: bold; }
    .connected { color: green; }
    .connecting { color: orange; }
    .disconnected, .error { color: red; }
    .data-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 16px; }
    .data-item { padding: 8px; background: #f0f0f0; border-radius: 4px; }
    .label { display: block; font-size: 0.8em; color: #555; }
    .value { font-size: 1.2em; font-weight: bold; }
    .state-running { color: #28a745; }
    .state-held { color: #ffc107; }
    .state-complete { color: #17a2b8; }
    .controls button { margin-right: 8px; padding: 8px 12px; }
  `,t.appendChild(b);let v=null,m=e.connectionStatus.subscribe(e=>{a.textContent=e,a.className=e,"connected"===e?(u.style.display="",p.style.display="none"):(u.style.display="none",p.style.display="block")}),g=e.getObservableForChannel("bioreactor.sk100.status").subscribe({next:e=>{(v=e)?(o.textContent=v.batchId||"N/A",s.textContent=v.state||"N/A",s.className=`value state-${(v.state||"").toLowerCase()}`,r.textContent=v.temperature?`${v.temperature.toFixed(2)} \xb0C`:"N/A",i.textContent=v.ph?`${v.ph.toFixed(2)}`:"N/A",c.textContent=v.dissolvedOxygen?`${v.dissolvedOxygen.toFixed(2)} mg/L`:"N/A",console.log(`[Bioreactor Monitor] Status updated: State is ${v.state}, Temp is ${v.temperature}`)):(o.textContent="Waiting...",s.textContent="N/A",s.className="value",r.textContent="N/A",i.textContent="N/A",c.textContent="N/A")},error:e=>{console.error("Bioreactor status stream error:",e)}}),x=t=>{console.log(`Sending command: ${t}`),e.publish("bioreactor.sk100.commands",{command:t,timestamp:new Date().toISOString()})};return l.addEventListener("click",()=>x("HOLD")),d.addEventListener("click",()=>x("RESTART")),e.connect({servers:["ws://nats.vishnefske.com:443"]}),new(0,n.Subscription)(()=>{m.unsubscribe(),g.unsubscribe(),l.removeEventListener("click",()=>x("HOLD")),d.removeEventListener("click",()=>x("RESTART"))})}});
//# sourceMappingURL=bioreactor-monitor.6fe93c4f.js.map
