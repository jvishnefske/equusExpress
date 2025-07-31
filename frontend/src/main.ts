import { NatsSignalsService } from './nats-signals.service';
import { initializeRouter } from './router';
import { BioreactorApp, PhysicalModelsModule, ControlProceduresModule, BatchMonitoringModule } from './interface'; // Correct casing and import modules

/**
 * Initializes the application, setting up NATS connection and routing.
 */
document.addEventListener('DOMContentLoaded', () => {
    // Initialize NATS Service first
    const natsService = new NatsSignalsService();

    // Connect to NATS when the application starts
    natsService.connect({
        servers: ['ws://nats.vishnefske.com:443'], // Use your NATS WebSocket endpoint
    }).catch(error => {
        console.error("Failed to connect to NATS:", error);
    });

    // Initialize the main application state manager
    const app = new BioreactorApp();

    // Initialize modules, passing the app instance
    // Note: These modules manage internal app state and listeners
    // They are not directly related to routing/display of main content views
    const physicalModels = new PhysicalModelsModule(app);
    const controlProcedures = new ControlProceduresModule(app);
    const batchMonitoring = new BatchMonitoringModule(app);

    // Call init on the app to set up navigation, load initial data, and start telemetry
    app.init();

    // Make app globally available for debugging (optional)
    (window as any).bioreactorApp = app; // Use 'any' to extend Window object

    // Initialize the router last, as it will render views that might depend on app/modules
    initializeRouter(natsService, app); // Pass app instance if needed by router functions

    console.log('Bioreactor Control System initialized');
});
