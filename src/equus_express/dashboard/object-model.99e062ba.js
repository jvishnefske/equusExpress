var e=globalThis.parcelRequire8661;(0,e.register)("6kXr5",function(n,t){Object.defineProperty(n.exports,"setupObjectModel",{get:()=>s,set:void 0,enumerable:!0,configurable:!0});var o=e("bgI6x");function s(e,n){let t=n||document.querySelector(".main-content");if(!t)return console.error("Object Model: Container element not found!"),new(0,o.Subscription);let s=["bioreactor.sk100.status","bioreactor.sk100.commands","some.other.data"],l=new Map;s.forEach(n=>{l.set(n,{channel:n,data:e.getObservableForChannel(n),subscription:null,element:null})}),t.innerHTML=`
    <div class="object-model-container">
      <h2>Object Model (NATS Channels)</h2>
      <div class="status-bar">
        NATS Connection: <span id="nats-om-connection-status">disconnected</span>
      </div>

      <div class="channel-list">
        <h3>Available Channels:</h3>
        <div id="channel-list-container">
          <!-- Channels will be injected here by JavaScript -->
        </div>
        <p id="no-channels-message" class="message" style="display: none;">No channels configured or available.</p>
      </div>
    </div>
  `;let a=t.querySelector("#nats-om-connection-status"),r=t.querySelector("#channel-list-container"),i=t.querySelector("#no-channels-message"),c=new(0,o.Subscription);return c.add(e.connectionStatus.subscribe(e=>{a.textContent=e,a.className=e})),0===s.length?i.style.display="block":(i.style.display="none",s.forEach(e=>{let n=document.createElement("div");n.className="channel-item",n.innerHTML=`
        <input type="checkbox" id="monitor-${e}" />
        <label for="monitor-${e}">${e}</label>
        <div class="channel-data" style="display: none;">
          <pre id="data-${e}"></pre>
        </div>
      `,r.appendChild(n);let t=n.querySelector(`#monitor-${e}`),o=n.querySelector(`#data-${e}`),s=n.querySelector(".channel-data");if(t&&o&&s){let n=l.get(e);n.element=o,t.addEventListener("change",()=>{t.checked?(s.style.display="block",n.subscription=n.data.subscribe({next:e=>{o.textContent=JSON.stringify(e,null,2)},error:n=>{o.textContent=`Error: ${n.message}`,console.error(`Error monitoring channel ${e}:`,n)},complete:()=>{o.textContent="Stream completed.",console.log(`Channel ${e} stream completed.`)}}),c.add(n.subscription)):(s.style.display="none",o.textContent="",n.subscription&&(n.subscription.unsubscribe(),c.remove(n.subscription),n.subscription=null))})}else console.error(`Object Model: Missing elements for channel ${e}.`)})),c}});
//# sourceMappingURL=object-model.99e062ba.js.map
