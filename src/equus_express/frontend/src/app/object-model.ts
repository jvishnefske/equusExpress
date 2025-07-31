import { NatsSignalsService, ConnectionStatus } from '@/nats-signals.service';
import { Observable, Subscription } from 'rxjs';

interface ChannelMonitor {
  channel: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: Observable<any | null>;
  subscription: Subscription | null;
  element: HTMLElement | null; // To hold the pre element for data display
}

/**
 * Sets up and renders the Object Model component into a given HTML element.
 * @param natsService The NatsSignalsService instance.
 * @param parentElement The HTML element where the object model should be rendered.
 */
export function setupObjectModel(natsService: NatsSignalsService, parentElement?: HTMLElement): Subscription {
  const container = parentElement || document.querySelector('.main-content');
  if (!container) {
    console.error('Object Model: Container element not found!');
    return new Subscription();
  }

  // The NATS connection is managed centrally by main.ts, so this reconnect logic is removed.
  // We will assume NATS service is already connected or will attempt to connect elsewhere.

  const preDefinedChannels = [
    'bioreactor.sk100.status',
    'bioreactor.sk100.commands',
    'some.other.data',
  ];

  // Initialize monitor state for each channel
  const channelMonitors: Map<string, ChannelMonitor> = new Map();
  preDefinedChannels.forEach(channel => {
    channelMonitors.set(channel, {
      channel: channel,
      data: natsService.getObservableForChannel(channel),
      subscription: null,
      element: null,
    });
  });

  // --- Render HTML Structure ---
  container.innerHTML = `
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
  `;

  // --- Get DOM Elements ---
  const connectionStatusSpan = container.querySelector<HTMLSpanElement>('#nats-om-connection-status')!;
  const channelListContainer = container.querySelector<HTMLDivElement>('#channel-list-container')!;
  const noChannelsMessage = container.querySelector<HTMLParagraphElement>('#no-channels-message')!;

  const subscriptions = new Subscription(); // To manage all RxJS subscriptions

  // --- Subscribe to NATS Connection Status ---
  subscriptions.add(
    natsService.connectionStatus.subscribe((status: ConnectionStatus) => {
      connectionStatusSpan.textContent = status;
      connectionStatusSpan.className = status; // Apply class for styling
    })
  );

  // --- Render Channels and Setup Event Listeners ---
  if (preDefinedChannels.length === 0) {
    noChannelsMessage.style.display = 'block';
  } else {
    noChannelsMessage.style.display = 'none';
    preDefinedChannels.forEach(channelName => {
      const channelItemDiv = document.createElement('div');
      channelItemDiv.className = 'channel-item';
      channelItemDiv.innerHTML = `
        <input type="checkbox" id="monitor-${channelName}" />
        <label for="monitor-${channelName}">${channelName}</label>
        <div class="channel-data" style="display: none;">
          <pre id="data-${channelName}"></pre>
        </div>
      `;
      channelListContainer.appendChild(channelItemDiv);

      const checkbox = channelItemDiv.querySelector<HTMLInputElement>(`#monitor-${channelName}`);
      const dataDisplayPre = channelItemDiv.querySelector<HTMLPreElement>(`#data-${channelName}`);
      const channelDataDiv = channelItemDiv.querySelector<HTMLDivElement>('.channel-data');

      // Add null checks for elements before proceeding with event listeners
      if (checkbox && dataDisplayPre && channelDataDiv) {
        const monitor = channelMonitors.get(channelName)!;
        monitor.element = dataDisplayPre; // Store reference to the element

        checkbox.addEventListener('change', () => {
          if (checkbox.checked) {
            channelDataDiv.style.display = 'block';
            // Subscribe when checkbox is checked
            monitor.subscription = monitor.data.subscribe({
              next: (data) => {
                dataDisplayPre.textContent = JSON.stringify(data, null, 2);
              },
              error: (err) => {
                dataDisplayPre.textContent = `Error: ${err.message}`;
                console.error(`Error monitoring channel ${channelName}:`, err);
              },
              complete: () => {
                dataDisplayPre.textContent = 'Stream completed.';
                console.log(`Channel ${channelName} stream completed.`);
              }
            });
            subscriptions.add(monitor.subscription); // Add to main subscriptions for cleanup
          } else {
            channelDataDiv.style.display = 'none';
            dataDisplayPre.textContent = ''; // Clear display
            // Unsubscribe when checkbox is unchecked
            if (monitor.subscription) {
              monitor.subscription.unsubscribe();
              subscriptions.remove(monitor.subscription);
              monitor.subscription = null;
            }
          }
        });
      } else {
          console.error(`Object Model: Missing elements for channel ${channelName}.`);
      }
    });
  }

  // Return the main subscription which will handle cleanup
  // This will primarily unsubscribe from the connection status.
  // Channel-specific subscriptions are managed by the checkboxes and added to 'subscriptions'
  // for comprehensive cleanup when setupObjectModel() is no longer active.
  return subscriptions;
}
