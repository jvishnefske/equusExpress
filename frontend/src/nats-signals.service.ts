import { Observable, Subject, BehaviorSubject, from } from 'rxjs';
import { map, takeUntil } from 'rxjs/operators';
import { wsconnect, Msg, SubscriptionOptions, ConnectionOptions } from '@nats-io/nats-core'; // Explicitly import types
// Define a type for the connection status for clarity
export type ConnectionStatus = 'connecting' | 'connected' | 'disconnected' | 'error';

/**
 * A service that bridges a NATS connection to a dynamic container of RxJS Observables.
 * Each NATS channel is mapped to a unique, readable Observable.
 *
 * Refactoring for testability:
 * - Introduced INatsClient interface to abstract NATS connection details.
 * - NatsSignalsService now accepts an optional INatsClient in its constructor, allowing for mock injection.
 */
export interface INatsClient {
  publish(subject: string, data?: Uint8Array): void;
  subscribe(subject: string, opts?: SubscriptionOptions): NatsSubscription;
  closed(): Promise<void>;
  drain(): Promise<void>;
}

/**
 * A service that bridges a NATS connection to a dynamic container of RxJS Observables.
 * Each NATS channel is mapped to a unique, readable Observable.
 */
export class NatsSignalsService {
  // A private container for the BehaviorSubjects. Key is the NATS channel name.
  private subjects = new Map<string, BehaviorSubject<any | null>>();
  
  // A Subject to signal when the service is being destroyed, for RxJS takeUntil operator
  private destroy$ = new Subject<void>();

  // Keep track of NATS subscriptions for potential cleanup
  private natsSubscriptions = new Map<string, NatsSubscription>();
  
  private natsClient: INatsClient | null = null; // Changed from natsConnection to natsClient

  /** Public, readable Observable for components to monitor the NATS connection status. */
  public readonly connectionStatus = new BehaviorSubject<ConnectionStatus>('disconnected');

  constructor(initialNatsClient?: INatsClient) {
    if (initialNatsClient) {
      this.natsClient = initialNatsClient;
      // If an initial client is provided, assume it's connected or handle its status
      this.connectionStatus.next('connected'); // Simplified for example, actual status could be inferred
    }
  }

  /**
   * Connects to the NATS server.
   * @param options NATS connection options (e.g., servers, user, pass).
   */
  public async connect(options: ConnectionOptions): Promise<void> {
    if (this.connectionStatus.getValue() === 'connected' || this.connectionStatus.getValue() === 'connecting') {
      console.warn('Already connected or connecting to NATS.');
      return;
    }

    try {
      this.connectionStatus.next('connecting');
      console.log('NATS: Connecting...');
      
      this.natsClient = await wsconnect(options); // Assign to natsClient
      this.connectionStatus.next('connected');
      console.log('NATS: Connection successful!');
      // Asynchronously handle connection closure
      (async () => {
        await this.natsClient?.closed();
        this.natsClient = null; // Set to null when connection is truly closed
        this.connectionStatus.next('disconnected');
        console.log('NATS: Connection closed.');
      })();

    } catch (err) {
      this.natsClient = null; // Ensure client is null on error
      this.connectionStatus.next('error');
      console.error('NATS: Connection failed.', err);
    }
  }

  /**
   * Gets a readable Observable for a specific NATS channel.
   * If the Observable doesn't exist, it creates one and subscribes to the channel.
   * This method is idempotent: multiple calls for the same channel return the same Observable.
   *
   * @param channel The NATS channel (subject) to subscribe to.
   * @param initialValue An optional initial value for the Observable.
   * @returns An Observable<T> that will be updated with messages from the channel.
   */
  public getObservableForChannel<T>(channel: string, initialValue: T | null = null): Observable<T | null> {
    // If a subject for this channel already exists, return its observable.
    if (this.subjects.has(channel)) {
      return this.subjects.get(channel)!.asObservable();
    }

    // Create a new BehaviorSubject with the provided initial value.
    const newSubject = new BehaviorSubject<T | null>(initialValue);
    this.subjects.set(channel, newSubject);

    // Subscribe to the NATS channel to update the new subject.
    this.subscribeToChannel<T>(channel, newSubject);

    // Return the subject as an observable to prevent direct outside emission.
    return newSubject.asObservable();
  }

  /**
   * Publishes data to a NATS channel.
   * @param channel The NATS channel (subject) to publish to.
   * @param data The data object to publish. It will be JSON-encoded.
   */
  public publish<T>(channel: string, data: T): void {
    if (!this.natsClient || this.connectionStatus.getValue() !== 'connected') {
      console.error('Cannot publish. NATS connection is not active.');
      return;
    }
    // NATS messages are payload agnostic; publish as a JSON string
    this.natsClient.publish(channel, JSON.stringify(data)); // Use natsClient
  }

  /**
   * Private method to handle the actual NATS subscription and message iteration.
   */
  private subscribeToChannel<T>(channel: string, subjectToUpdate: BehaviorSubject<T | null>): void {
    if (!this.natsClient || this.connectionStatus.getValue() !== 'connected') {
      console.error(`Cannot subscribe to "${channel}". NATS is not connected.`);
      subjectToUpdate.error(new Error(`NATS not connected for channel ${channel}`));
      return;
    }
    
    // Ensure only one NATS subscription per channel
    if (this.natsSubscriptions.has(channel)) {
        console.warn(`NATS: Already subscribed to channel "${channel}".`);
        return;
    }

    const sub = this.natsClient.subscribe(channel); // Use natsClient
    this.natsSubscriptions.set(channel, sub);
    console.log(`NATS: Subscribed to channel "${channel}".`);

    // Convert NATS message iterator to an RxJS observable, using msg.json() for decoding
    from(sub)
      .pipe(
        map((msg: Msg) => { // Explicitly type msg as Msg
          try {
            return msg.json() as T; // Use the built-in json() method
          } catch (err) {
            console.error(`Failed to parse JSON from channel "${channel}":`, msg.data, err);
            throw err; // Re-throw to propagate error to RxJS stream
          }
        }),
        takeUntil(this.destroy$) // Unsubscribe when the service is destroyed
      )
      .subscribe({
        next: data => subjectToUpdate.next(data),
        error: err => {
            console.error(`Error in NATS subscription for channel "${channel}":`, err);
            subjectToUpdate.error(err);
            this.natsSubscriptions.delete(channel); // Clean up the NATS subscription record
        },
        complete: () => {
            console.log(`NATS: Subscription to "${channel}" completed.`);
            subjectToUpdate.complete();
            this.natsSubscriptions.delete(channel); // Clean up the NATS subscription record
        }
      });
  }

  /**
   * Gracefully drains the connection and cleans up all RxJS subscriptions.
   */
  public async destroy(): Promise<void> {
    this.destroy$.next(); // Signal all active RxJS subscriptions to complete
    this.destroy$.complete();

    // Close all NATS subscriptions
    for (const sub of this.natsSubscriptions.values()) {
        await sub.unsubscribe(); // Await unsubscribe if it's an async operation (though NATS.js usually handles this internally with drain)
    }
    this.natsSubscriptions.clear();

    // Clear all subjects
    this.subjects.forEach(subject => subject.complete());
    this.subjects.clear();

    if (this.natsClient) { // Use natsClient
      console.log('NATS: Draining connection...');
      await this.natsClient.drain(); // Use natsClient
      this.natsClient = null; // Use natsClient
    }
    this.connectionStatus.complete();
  }
}
