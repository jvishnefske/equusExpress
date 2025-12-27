import { NatsSignalsService, INatsClient, ConnectionStatus } from './nats-signals.service';
import { BehaviorSubject, firstValueFrom } from 'rxjs';
import { Msg, Subscription as NatsSubscription, SubscriptionOptions } from '@nats-io/nats-core'; // Import necessary types

/**
 * Mock implementation of NatsSubscription to simulate an AsyncIterable and allow manual message pushing.
 * This also needs to implement `unsubscribe` to be a valid NatsSubscription.
 */
class MockNatsSubscription implements NatsSubscription {
    // We use a BehaviorSubject to simulate the asynchronous message stream
    private messages = new BehaviorSubject<Msg | null>(null);
    private _isUnsubscribed = false;

    // AsyncIterator implementation
    async next(): Promise<IteratorResult<Msg>> {
        if (this._isUnsubscribed) {
            return { value: undefined, done: true };
        }
        // Wait for the next message or completion
        const msg = await firstValueFrom(this.messages.asObservable());
        if (msg === null) { // Signifies completion
            return { value: undefined, done: true };
        }
        return { value: msg, done: false };
    }

    [Symbol.asyncIterator](): AsyncIterator<Msg> {
        return this;
    }

    // NatsSubscription interface methods
    getSubject(): string { return 'mock.subject'; } // Dummy implementation
    getReceived(): number { return 0; } // Dummy implementation
    getPending(): number { return 0; } // Dummy implementation
    getMaxPending(): number { return 0; } // Dummy implementation
    getID(): number { return 1; } // Dummy implementation
    getSid(): number { return 1; } // Dummy implementation
    isClosed(): boolean { return this._isUnsubscribed; }

    async unsubscribe(): Promise<void> {
        this._isUnsubscribed = true;
        this.messages.complete(); // Complete the subject when unsubscribed
    }

    async drain(): Promise<void> {
        return this.unsubscribe(); // Simple drain for mock
    }

    // Method for tests to push a new message into the stream
    public addMessage(data: any): void {
        const mockMsg: Msg = {
            subject: this.getSubject(),
            sid: this.getSid(),
            data: new TextEncoder().encode(JSON.stringify(data)),
            json: () => data, // Simulate json() method
            string: () => JSON.stringify(data), // Simulate string() method
            headers: undefined,
            reply: undefined,
            respond: () => {},
            seq: 0,
            time: 0,
            token: ""
        };
        this.messages.next(mockMsg);
    }

    // Method for tests to signal completion of the stream
    public complete(): void {
        this.messages.complete();
        this._isUnsubscribed = true;
    }
}

/**
 * Mock implementation of INatsClient for testing NatsSignalsService.
 */
class MockNatsClient implements INatsClient {
    public publishedMessages: { subject: string; data: Uint8Array }[] = [];
    public subscriptions = new Map<string, MockNatsSubscription>();
    private _isClosed = false;
    private _closedPromise: Promise<void>;
    private _resolveClosedPromise!: () => void; // Non-null assertion, will be initialized in constructor

    constructor() {
        this._closedPromise = new Promise(resolve => {
            this._resolveClosedPromise = resolve;
        });
    }

    isClosed(): boolean {
        return this._isClosed;
    }

    publish(subject: string, data?: Uint8Array): void {
        this.publishedMessages.push({ subject, data: data || new Uint8Array() });
    }

    subscribe(subject: string, opts?: SubscriptionOptions): NatsSubscription {
        let sub = this.subscriptions.get(subject);
        if (!sub) {
            sub = new MockNatsSubscription();
            this.subscriptions.set(subject, sub);
        }
        return sub;
    }

    async closed(): Promise<void> {
        return this._closedPromise;
    }

    async drain(): Promise<void> {
        this._isClosed = true;
        this._resolveClosedPromise(); // Resolve the closed promise when drained
        // Simulate drain completing all active subscriptions
        this.subscriptions.forEach(sub => sub.complete());
    }

    // Helper method for tests to push messages into a specific subscription
    public pushMessage(subject: string, data: any): void {
        const sub = this.subscriptions.get(subject);
        if (sub) {
            sub.addMessage(data);
        } else {
            console.warn(`No active mock subscription for subject: ${subject}. Message not pushed.`);
        }
    }

    // Helper method for tests to simulate the client closing from external force
    public simulateClose(): void {
        this._isClosed = true;
        this._resolveClosedPromise();
        this.subscriptions.forEach(sub => sub.complete());
    }
}

describe('NatsSignalsService', () => {
    let service: NatsSignalsService;
    let mockNatsClient: MockNatsClient;

    // Before each test, create a new service instance with a fresh mock client
    beforeEach(() => {
        mockNatsClient = new MockNatsClient();
        service = new NatsSignalsService(mockNatsClient);
    });

    // After each test, destroy the service to clean up subscriptions
    afterEach(async () => {
        await service.destroy();
    });

    it('should be created and initially connected if a client is provided', async () => {
        expect(service).toBeTruthy();
        // Check initial connection status if client is injected
        let status: ConnectionStatus | undefined;
        service.connectionStatus.subscribe(s => status = s);
        expect(status).toBe('connected');
    });

    it('should reflect "connecting" and "connected" status on real connect if no client provided', async () => {
        // Create a service without an injected client to test the `connect` method
        const realService = new NatsSignalsService();
        const statusUpdates: ConnectionStatus[] = [];
        realService.connectionStatus.subscribe(s => statusUpdates.push(s));

        // Mock the global connect function temporarily for this test
        const originalConnect = (await import('@nats-io/nats-core')).connect;
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        const mockRealNatsConnection = {
            closed: () => Promise.resolve(), // Immediately resolve closed for test cleanup
            drain: () => Promise.resolve(),
            isClosed: () => false,
            publish: () => {},
            subscribe: () => ({ // Mock a simple subscription object
                unsubscribe: () => Promise.resolve(),
                drain: () => Promise.resolve(),
                getSubject: () => 'mock.subject',
                getReceived: () => 0,
                getPending: () => 0,
                getMaxPending: () => 0,
                getID: () => 1,
                getSid: () => 1,
                isClosed: () => false,
                [Symbol.asyncIterator]: async function*() {}
            })
        };
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        jest.spyOn(await import('@nats-io/nats-core'), 'connect').mockResolvedValue(mockRealNatsConnection);

        await realService.connect({ servers: ['ws://test.nats.io:8080'] });

        expect(statusUpdates).toEqual(['disconnected', 'connecting', 'connected']);
        expect(realService['natsClient']).toBe(mockRealNatsConnection); // Access private for assertion
        await realService.destroy();
        // Restore original connect function
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        (await import('@nats-io/nats-core')).connect = originalConnect;
    });

    it('should reflect "error" status on real connect failure', async () => {
        const realService = new NatsSignalsService();
        const statusUpdates: ConnectionStatus[] = [];
        realService.connectionStatus.subscribe(s => statusUpdates.push(s));

        // Mock the global connect function to throw an error
        const originalConnect = (await import('@nats-io/nats-core')).connect;
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        jest.spyOn(await import('@nats-io/nats-core'), 'connect').mockRejectedValue(new Error('Connection refused'));

        await realService.connect({ servers: ['ws://test.nats.io:8080'] });

        expect(statusUpdates).toEqual(['disconnected', 'connecting', 'error']);
        await realService.destroy();
        // Restore original connect function
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        (await import('@nats-io/nats-core')).connect = originalConnect;
    });

    it('should return a BehaviorSubject for a channel', () => {
        const channel = 'test.channel';
        const obs = service.getObservableForChannel(channel);
        expect(obs).toBeInstanceOf(BehaviorSubject);
    });

    it('should return the same BehaviorSubject for the same channel', () => {
        const channel = 'test.channel';
        const obs1 = service.getObservableForChannel(channel);
        const obs2 = service.getObservableForChannel(channel);
        expect(obs1).toBe(obs2);
    });

    it('should subscribe to NATS when an observable is requested for a new channel', () => {
        const channel = 'new.channel';
        service.getObservableForChannel(channel);
        expect(mockNatsClient.subscriptions.has(channel)).toBe(true);
    });

    it('should not subscribe to NATS again if already subscribed to the channel', () => {
        const channel = 'duplicate.channel';
        service.getObservableForChannel(channel); // First subscription
        const subscribeSpy = jest.spyOn(mockNatsClient, 'subscribe');
        service.getObservableForChannel(channel); // Second call for same channel
        expect(subscribeSpy).not.toHaveBeenCalled(); // Should not call subscribe again
        subscribeSpy.mockRestore();
    });

    it('should receive messages published to the subscribed channel', (done) => {
        const channel = 'data.channel';
        const testData1 = { value: 1 };
        const testData2 = { value: 2 };

        const obs = service.getObservableForChannel(channel);
        const receivedData: any[] = [];

        obs.subscribe(data => {
            if (data !== null) { // Ignore initial null
                receivedData.push(data);
            }
            if (receivedData.length === 2) {
                expect(receivedData).toEqual([testData1, testData2]);
                done();
            }
        });

        // Simulate NATS server pushing messages
        mockNatsClient.pushMessage(channel, testData1);
        mockNatsClient.pushMessage(channel, testData2);
    });

    it('should publish messages through the NATS client', () => {
        const channel = 'publish.channel';
        const message = { type: 'command', action: 'start' };

        service.publish(channel, message);

        expect(mockNatsClient.publishedMessages.length).toBe(1);
        expect(mockNatsClient.publishedMessages[0].subject).toBe(channel);
        expect(JSON.parse(new TextDecoder().decode(mockNatsClient.publishedMessages[0].data)))
            .toEqual(message);
    });

    it('should not publish if NATS client is closed', () => {
        mockNatsClient.simulateClose(); // Manually close the mock client
        const channel = 'closed.channel';
        const message = { data: 'test' };

        service.publish(channel, message);

        expect(mockNatsClient.publishedMessages.length).toBe(0);
    });

    it('should clean up all subscriptions on destroy', async () => {
        const channel1 = 'channel.one';
        const channel2 = 'channel.two';

        service.getObservableForChannel(channel1);
        service.getObservableForChannel(channel2);

        const sub1 = mockNatsClient.subscriptions.get(channel1) as MockNatsSubscription;
        const sub2 = mockNatsClient.subscriptions.get(channel2) as MockNatsSubscription;

        const spy1 = jest.spyOn(sub1, 'unsubscribe');
        const spy2 = jest.spyOn(sub2, 'unsubscribe');

        await service.destroy();

        expect(spy1).toHaveBeenCalled();
        expect(spy2).toHaveBeenCalled();
        expect(service['subjects'].size).toBe(0); // Access private for assertion
        expect(service['natsSubscriptions'].size).toBe(0); // Access private for assertion
    });

    it('should drain the NATS client on destroy', async () => {
        const drainSpy = jest.spyOn(mockNatsClient, 'drain');
        await service.destroy();
        expect(drainSpy).toHaveBeenCalled();
        expect(mockNatsClient.isClosed()).toBe(true);
    });

    it('should handle errors in message parsing', (done) => {
        const channel = 'error.channel';
        const obs = service.getObservableForChannel(channel);
        let errorReceived: any;

        obs.subscribe({
            next: () => {}, // Should not receive next
            error: (err) => {
                errorReceived = err;
                expect(errorReceived).toBeInstanceOf(Error);
                expect(errorReceived.message).toContain('Failed to parse JSON');
                done();
            },
            complete: () => {}
        });

        // Simulate NATS pushing a malformed message
        const mockBadMsg: Msg = {
            subject: channel,
            sid: 1,
            data: new TextEncoder().encode('not-json'), // Malformed data
            json: () => { throw new Error('Failed to parse JSON from NATS msg'); }, // Simulate json() throwing
            string: () => 'not-json',
            headers: undefined,
            reply: undefined,
            respond: () => {},
            seq: 0,
            time: 0,
            token: ""
        };

        const mockSub = mockNatsClient.subscriptions.get(channel) as MockNatsSubscription;
        if (mockSub) {
            // Manually push the malformed message
            // eslint-disable-next-line @typescript-eslint/ban-ts-comment
            // @ts-ignore
            mockSub.messages.next(mockBadMsg);
        }
    });

    it('should complete subject and remove natsSubscription on NATS subscription complete', (done) => {
        const channel = 'complete.channel';
        const obs = service.getObservableForChannel(channel);
        let completed = false;
        
        obs.subscribe({
            next: () => {},
            error: () => {},
            complete: () => {
                completed = true;
                expect(completed).toBe(true);
                expect(service['subjects'].has(channel)).toBe(true); // Subject should still exist in map
                expect(service['natsSubscriptions'].has(channel)).toBe(false); // NATS subscription should be removed
                done();
            }
        });

        const mockSub = mockNatsClient.subscriptions.get(channel) as MockNatsSubscription;
        mockSub.complete(); // Simulate NATS subscription completing
    });

    it('should handle connection status updates after simulated external close', (done) => {
        const statusUpdates: ConnectionStatus[] = [];
        service.connectionStatus.subscribe(s => {
            statusUpdates.push(s);
            if (s === 'disconnected' && statusUpdates.length === 2) {
                expect(statusUpdates).toEqual(['connected', 'disconnected']);
                done();
            }
        });

        // Simulate the NATS client being closed externally (e.g., server disconnect)
        mockNatsClient.simulateClose();
    });
});
