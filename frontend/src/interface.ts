
// Application State Management
export class BioreactorApp {
    // Add types for these properties for better type safety
    models: Map<string, any>;
    recipes: Map<string, any>;
    bioreactors: Map<string, any>;
    telemetryData: Map<string, any>; // Consider a more specific type for telemetry data

    constructor() {
        this.models = new Map();
        this.recipes = new Map();
        this.bioreactors = new Map();
        this.telemetryData = new Map();

        // init() is now called from main.ts after modules are instantiated
    }

    init() {
        this.setupNavigation();
        this.loadInitialData();
        this.startTelemetrySimulation();
    }

    setupNavigation() {
        // This navigation is for the internal sections of the interface.ts file
        // It might conflict with the router.ts. Let's keep it for now but note the potential for refactor.
        const navItems = document.querySelectorAll('.nav-item');
        const sections = document.querySelectorAll('.view'); // Changed to .view as per index.html

        navItems.forEach(item => {
            item.addEventListener('click', (event) => {
                // Prevent router from handling this nav item if it's meant for internal section toggling
                // If routerLink is present, router will handle it. Otherwise, this internal handler.
                if (!item.closest('a')?.getAttribute('routerLink')) {
                    event.preventDefault(); // Stop default link behavior
                    const sectionId = item.getAttribute('data-section');

                    // Update nav active state for internal nav items
                    navItems.forEach(nav => nav.classList.remove('active'));
                    item.classList.add('active');

                    // Update section visibility
                    sections.forEach(section => {
                        if (section instanceof HTMLElement) { // Type guard
                            section.style.display = 'none'; // Hide all views
                        }
                    });
                    const targetSection = document.getElementById(sectionId!); // sectionId should not be null here
                    if (targetSection) {
                        targetSection.style.display = 'block'; // Show target view
                    }
                }
            });
        });
    }

    loadInitialData() {
        // Initialize models
        this.models.set('standard-v2', {
            id: 'standard-v2',
            name: 'Standard Bioreactor v2.1',
            workingVolume: 10.0,
            maxTemp: 37.0,
            pHRange: 8,
            maxRPM: 500,
            active: true
        });

        // Initialize recipes with stages
        this.recipes.set('standard-fermentation', {
            id: 'standard-fermentation',
            name: 'Standard Fermentation Recipe',
            stages: [
                { id: 1, name: 'Sterilization', description: '121°C for 15 minutes', status: 'complete' },
                { id: 2, name: 'Cooling', description: 'Cool to 37°C', status: 'complete' },
                { id: 3, name: 'Inoculation', description: 'Add culture, pH 7.0', status: 'current' },
                { id: 4, name: 'Growth Phase', description: '24-48 hours', status: 'pending' },
                { id: 5, name: 'Production Phase', description: '72 hours', status: 'pending' },
                { id: 6, name: 'Harvest', description: 'Collection and cleanup', status: 'pending' }
            ]
        });

        // Initialize bioreactors
        this.bioreactors.set('BR-001', {
            id: 'BR-001',
            name: 'Bioreactor BR-001',
            modelId: 'standard-v2',
            status: 'running',
            currentStage: 3,
            totalStages: 6,
            progress: 50,
            runtime: '6h 45m',
            portMapping: {
                'Temp Probe': 'AI-1',
                'pH Probe': 'AI-2',
                'DO Probe': 'AI-3',
                'Agitator': 'AO-1'
            }
        });

        this.bioreactors.set('BR-002', {
            id: 'BR-002',
            name: 'Bioreactor BR-002',
            modelId: 'high-throughput-v1',
            status: 'complete',
            currentStage: 6,
            totalStages: 6,
            progress: 100,
            runtime: '4d 12h 30m',
            portMapping: {
                'Temp Probe': 'AI-4',
                'pH Probe': 'AI-5',
                'DO Probe': 'AI-6',
                'Agitator': 'AO-2'
            }
        });

        this.bioreactors.set('BR-003', {
            id: 'BR-003',
            name: 'Bioreactor BR-003',
            modelId: 'large-scale-v3',
            status: 'fault',
            currentStage: 4,
            totalStages: 6,
            progress: 67,
            fault: 'pH out of range',
            portMapping: {
                'Temp Probe': 'AI-7',
                'pH Probe': 'AI-8',
                'DO Probe': 'AI-9',
                'Agitator': 'AO-3'
            }
        });
    }

    startTelemetrySimulation() {
        // Simulate real-time telemetry updates
        setInterval(() => {
            this.updateTelemetry();
        }, 2000);
    }

    updateTelemetry() {
        // Simulate telemetry data updates
        const bioreactors = document.querySelectorAll('.bioreactor-card');

        bioreactors.forEach((card, index) => {
            const telemetryValues = card.querySelectorAll('.telemetry-value');

            if (index === 0) { // BR-001 - Running
                // Add small random variations
                const temp = 37.0 + (Math.random() - 0.5) * 0.2;
                const pH = 7.1 + (Math.random() - 0.5) * 0.1;
                const DO = 85 + (Math.random() - 0.5) * 5;
                const RPM = 150 + (Math.random() - 0.5) * 5;

                telemetryValues[0].textContent = temp.toFixed(1);
                telemetryValues[1].textContent = pH.toFixed(1);
                telemetryValues[2].textContent = Math.round(DO).toString(); // Ensure string
                telemetryValues[3].textContent = Math.round(RPM).toString(); // Ensure string
            }
        });
    }

    // Module Communication System
    publishEvent(eventType: string, data: any) {
        // Loosely coupled module communication
        window.dispatchEvent(new CustomEvent(eventType, { detail: data }));
    }

    subscribeToEvent(eventType: string, handler: (event: CustomEvent) => void) {
        window.addEventListener(eventType, handler as EventListener);
    }

    // Stage Management
    advanceStage(bioreactorId: string) {
        const bioreactor = this.bioreactors.get(bioreactorId);
        if (bioreactor && bioreactor.currentStage < bioreactor.totalStages) {
            bioreactor.currentStage++;
            bioreactor.progress = (bioreactor.currentStage / bioreactor.totalStages) * 100;

            this.publishEvent('stageAdvanced', {
                bioreactorId,
                stage: bioreactor.currentStage
            });
        }
    }

    resetBatch(bioreactorId: string) {
        const bioreactor = this.bioreactors.get(bioreactorId);
        if (bioreactor) {
            bioreactor.currentStage = 1;
            bioreactor.progress = 0;
            bioreactor.status = 'running';
            bioreactor.fault = null;

            this.publishEvent('batchReset', { bioreactorId });
        }
    }

    // Model Management
    addModel(modelData: any) {
        this.models.set(modelData.id, modelData);
        this.publishEvent('modelAdded', modelData);
    }

    updateModel(modelId: string, updates: any) {
        const model = this.models.get(modelId);
        if (model) {
            Object.assign(model, updates);
            this.publishEvent('modelUpdated', { modelId, updates });
        }
    }

    // Recipe Management
    addRecipe(recipeData: any) {
        this.recipes.set(recipeData.id, recipeData);
        this.publishEvent('recipeAdded', recipeData);
    }

    updateRecipeStage(recipeId: string, stageId: number, updates: any) {
        const recipe = this.recipes.get(recipeId);
        if (recipe) {
            const stage = recipe.stages.find((s: any) => s.id === stageId); // Added type for s
            if (stage) {
                Object.assign(stage, updates);
                this.publishEvent('recipeStageUpdated', { recipeId, stageId, updates });
            }
        }
    }

    // Gating Criteria Validation
    validateGatingCriteria(bioreactorId: string, stageId: number) {
        const bioreactor = this.bioreactors.get(bioreactorId);
        if (!bioreactor) return false;

        // Get current telemetry
        const telemetry = this.getCurrentTelemetry(bioreactorId);

        // Example gating criteria for stage 3 (Inoculation)
        if (stageId === 3) {
            const tempOK = Math.abs(telemetry.temperature - 37.0) <= 0.5;
            const pHOK = Math.abs(telemetry.pH - 7.0) <= 0.2;
            const doOK = telemetry.dissolvedO2 > 80;
            const rpmOK = telemetry.rpm === 150;

            return tempOK && pHOK && doOK && rpmOK;
        }

        return true; // Default pass for other stages
    }

    getCurrentTelemetry(bioreactorId: string) {
        // Get current telemetry data for a bioreactor
        return this.telemetryData.get(bioreactorId) || {
            temperature: 37.0,
            pH: 7.1,
            dissolvedO2: 85,
            rpm: 150
        };
    }

    // NATS Integration (placeholder for real implementation)
    async connectToNATS() {
        try {
            if ((window as any).natsCore) { // Use 'any' to access natsCore on window
                // Example NATS connection
                console.log('NATS Core available for real-time communication');
                // const nc = await (window as any).natsCore.connect({ servers: "ws://localhost:8080" });
                // return nc;
            }
        } catch (error) {
            console.log('NATS connection not available:', error);
        }
        return null;
    }
}

// Physical Models Module
export class PhysicalModelsModule {
    app: BioreactorApp; // Explicitly type app

    constructor(app: BioreactorApp) { // Explicitly type app
        this.app = app;
        this.init();
    }

    init() {
        // Subscribe to model events
        this.app.subscribeToEvent('modelAdded', this.onModelAdded.bind(this));
        this.app.subscribeToEvent('modelUpdated', this.onModelUpdated.bind(this));

        // Setup UI interactions
        this.setupModelInteractions();
    }

    setupModelInteractions() {
        // Add event listeners for model management
        const newModelBtn = document.querySelector('[data-section="physical-models"] .btn-primary');
        if (newModelBtn) {
            newModelBtn.addEventListener('click', this.showNewModelDialog.bind(this));
        }
    }

    onModelAdded(event: CustomEvent) { // Explicitly type event
        console.log('Model added:', event.detail);
        this.refreshModelsDisplay();
    }

    onModelUpdated(event: CustomEvent) { // Explicitly type event
        console.log('Model updated:', event.detail);
        this.refreshModelsDisplay();
    }

    showNewModelDialog() {
        // Placeholder for model creation dialog
        console.log('Show new model dialog');
    }

    refreshModelsDisplay() {
        // Update the models list display
        console.log('Refreshing models display');
    }
}

// Control Procedures Module
export class ControlProceduresModule {
    app: BioreactorApp; // Explicitly type app

    constructor(app: BioreactorApp) { // Explicitly type app
        this.app = app;
        this.init();
    }

    init() {
        // Subscribe to recipe events
        this.app.subscribeToEvent('recipeAdded', this.onRecipeAdded.bind(this));
        this.app.subscribeToEvent('recipeStageUpdated', this.onRecipeStageUpdated.bind(this));

        this.setupRecipeInteractions();
    }

    setupRecipeInteractions() {
        // Setup stage editing and recipe management
        const editStageBtn = document.querySelector('[data-section="control-procedures"] .btn-primary');
        if (editStageBtn) {
            editStageBtn.addEventListener('click', this.editCurrentStage.bind(this));
        }
    }

    onRecipeAdded(event: CustomEvent) { // Explicitly type event
        console.log('Recipe added:', event.detail);
    }

    onRecipeStageUpdated(event: CustomEvent) { // Explicitly type event
        console.log('Recipe stage updated:', event.detail);
    }

    editCurrentStage() {
        console.log('Edit current stage');
        // Show stage editing interface
    }

    validateStageCompletion(stageId: number, criteria: any) { // Explicitly type parameters
        // Validate if stage completion criteria are met
        return this.app.validateGatingCriteria('BR-001', stageId);
    }
}

// Batch Monitoring Module
export class BatchMonitoringModule {
    app: BioreactorApp; // Explicitly type app

    constructor(app: BioreactorApp) { // Explicitly type app
        this.app = app;
        this.init();
    }

    init() {
        // Subscribe to batch events
        this.app.subscribeToEvent('stageAdvanced', this.onStageAdvanced.bind(this));
        this.app.subscribeToEvent('batchReset', this.onBatchReset.bind(this));

        this.setupMonitoringInteractions();
        this.startTelemetryDisplay();
    }

    setupMonitoringInteractions() {
        // Setup reset and log viewing buttons
        const resetBtns = document.querySelectorAll('[data-section="batch-monitoring"] .btn-primary');
        resetBtns.forEach(btn => {
            if (btn.textContent === 'Reset Batch') {
                btn.addEventListener('click', () => {
                    const bioreactorId = 'BR-003'; // Get from context
                    this.app.resetBatch(bioreactorId);
                });
            }
        });
    }

    onStageAdvanced(event: CustomEvent) { // Explicitly type event
        console.log('Stage advanced:', event.detail);
        this.updateBatchDisplay(event.detail.bioreactorId);
    }

    onBatchReset(event: CustomEvent) { // Explicitly type event
        console.log('Batch reset:', event.detail);
        this.updateBatchDisplay(event.detail.bioreactorId);
    }

    updateBatchDisplay(bioreactorId: string) { // Explicitly type parameter
        // Update the display for a specific bioreactor
        console.log('Updating batch display for:', bioreactorId);
    }

    startTelemetryDisplay() {
        // Real-time telemetry display updates
        setInterval(() => {
            this.updateTelemetryDisplays();
        }, 1000);
    }

    updateTelemetryDisplays() {
        // Update telemetry values in the UI
        // This is handled by the main app's updateTelemetry method
    }
}

// Removed the DOMContentLoaded listener from here.
// Initialization will now happen in main.ts
