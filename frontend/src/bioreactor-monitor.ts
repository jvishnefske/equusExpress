import { NatsSignalsService } from './nats-signals.service';
import { Subscription } from 'rxjs'; // Keep RxJS as NatsSignalsService uses it

// Define an interface for our data for type safety
interface BioreactorStatus {
  batchId: string;
  temperature: number;
  ph: number;
  dissolvedOxygen: number;
  state: 'RUNNING' | 'HELD' | 'COMPLETE';
}

/**
 * Sets up and manages the Bioreactor Monitor display within a given HTML element.
 * @param natsService The NatsSignalsService instance.
 * @param parentElement The HTMLElement where the monitor should be rendered.
 * @returns A Subscription that can be used to clean up the monitor when no longer needed.
 */
export function setupBioreactorMonitor(natsService: NatsSignalsService, parentElement: HTMLElement): Subscription {
  const container = parentElement; // The provided parentElement is our container

  // Create the basic structure
  container.innerHTML = `
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
  `;

  // Get references to elements for dynamic updates
  const natsStatusEl = container.querySelector('#nats-connection-status') as HTMLSpanElement;
  const batchIdEl = container.querySelector('#batch-id') as HTMLSpanElement;
  const stateValueEl = container.querySelector('#state-value') as HTMLSpanElement;
  const temperatureValueEl = container.querySelector('#temperature-value') as HTMLSpanElement;
  const phValueEl = container.querySelector('#ph-value') as HTMLSpanElement;
  const doValueEl = container.querySelector('#do-value') as HTMLSpanElement;
  const holdButton = container.querySelector('#hold-button') as HTMLButtonElement;
  const restartButton = container.querySelector('#restart-button') as HTMLButtonElement;
  const bioreactorContent = container.querySelector('#bioreactor-content') as HTMLDivElement;
  const disconnectedMessage = container.querySelector('#disconnected-message') as HTMLParagraphElement;

  // Apply styles directly (or ensure they are loaded via CSS file)
  const styleEl = document.createElement('style');
  styleEl.textContent = `
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
  `;
  container.appendChild(styleEl);

  let currentStatus: BioreactorStatus | null = null; // Hold current status

  // Subscribe to NATS connection status
  const connectionStatusSub = natsService.connectionStatus.subscribe(status => {
    natsStatusEl.textContent = status;
    natsStatusEl.className = status; // Apply class for styling
    if (status === 'connected') {
      bioreactorContent.style.display = '';
      disconnectedMessage.style.display = 'none';
    } else {
      bioreactorContent.style.display = 'none';
      disconnectedMessage.style.display = 'block';
    }
  });

  // Subscribe to bioreactor status channel
  const bioreactorStatusSub = natsService.getObservableForChannel<BioreactorStatus>('bioreactor.sk100.status').subscribe({
    next: (statusData) => {
      currentStatus = statusData;
      if (currentStatus) {
        batchIdEl.textContent = currentStatus.batchId || 'N/A';
        stateValueEl.textContent = currentStatus.state || 'N/A';
        stateValueEl.className = `value state-${(currentStatus.state || '').toLowerCase()}`;
        temperatureValueEl.textContent = currentStatus.temperature ? `${currentStatus.temperature.toFixed(2)} °C` : 'N/A';
        phValueEl.textContent = currentStatus.ph ? `${currentStatus.ph.toFixed(2)}` : 'N/A';
        doValueEl.textContent = currentStatus.dissolvedOxygen ? `${currentStatus.dissolvedOxygen.toFixed(2)} mg/L` : 'N/A';
        
        console.log(`[Bioreactor Monitor] Status updated: State is ${currentStatus.state}, Temp is ${currentStatus.temperature}`);
      } else {
        batchIdEl.textContent = 'Waiting...';
        stateValueEl.textContent = 'N/A';
        stateValueEl.className = 'value';
        temperatureValueEl.textContent = 'N/A';
        phValueEl.textContent = 'N/A';
        doValueEl.textContent = 'N/A';
      }
    },
    error: (err) => {
      console.error('Bioreactor status stream error:', err);
      // Handle error display if necessary
    }
  });

  // Event listeners for buttons
  const sendCommand = (command: 'HOLD' | 'RESTART') => {
    console.log(`Sending command: ${command}`);
    natsService.publish('bioreactor.sk100.commands', {
      command: command,
      timestamp: new Date().toISOString()
    });
  };

  holdButton.addEventListener('click', () => sendCommand('HOLD'));
  restartButton.addEventListener('click', () => sendCommand('RESTART'));

  // Initial connection
  natsService.connect({
    servers: ['ws://nats.vishnefske.com:443'],
  });

  // Return a subscription that can be used to unsubscribe from all NATS and DOM event listeners
  return new Subscription(() => {
    connectionStatusSub.unsubscribe();
    bioreactorStatusSub.unsubscribe();
    holdButton.removeEventListener('click', () => sendCommand('HOLD'));
    restartButton.removeEventListener('click', () => sendCommand('RESTART'));
    // Optionally remove the element itself or clear its content if that's desired for cleanup
    // container.innerHTML = '';
    // container.removeChild(styleEl);
  });
}
