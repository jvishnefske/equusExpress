import * as Blockly from 'blockly';
import { javascriptGenerator } from 'blockly/javascript';
import { Recipe, Stage, IMachineService, PhysicalModel } from './models'; // Ensure Stage, IMachineService, PhysicalModel are imported if used for types
import { configureBlockly } from './blockly-setup';
import { fermentationModel, MachineService } from './machine.service';
import { NatsSignalsService } from './nats-signals.service'; // Import NatsSignalsService

// A default empty state for a new blockly workspace
const emptyWorkspace: string = '<xml xmlns="https://developers.google.com/blockly/xml"></xml>';

// The main recipe data, mirroring the UI image
const recipe: Recipe = {
    name: "Standard Fermentation Recipe",
    stages: [
        { id: 1, name: 'Sterilization', description: '121°C for 15 minutes', gatingCriteria: emptyWorkspace, actions: emptyWorkspace, completionCriteria: emptyWorkspace },
        { id: 2, name: 'Cooling', description: 'Cool to 37°C', gatingCriteria: emptyWorkspace, actions: emptyWorkspace, completionCriteria: emptyWorkspace },
        { id: 3, name: 'Inoculation', description: 'Add culture, pH 7.0', gatingCriteria: emptyWorkspace, actions: emptyWorkspace, completionCriteria: emptyWorkspace },
        { id: 4, name: 'Growth Phase', description: '24-48 hours', gatingCriteria: emptyWorkspace, actions: emptyWorkspace, completionCriteria: emptyWorkspace },
        { id: 5, name: 'Production Phase', description: '72 hours', gatingCriteria: emptyWorkspace, actions: emptyWorkspace, completionCriteria: emptyWorkspace },
        { id: 6, name: 'Harvest', description: 'Collection and cleanup', gatingCriteria: emptyWorkspace, actions: emptyWorkspace, completionCriteria: emptyWorkspace },
    ]
};

// Global variables (now local to the setup function for better encapsulation)
let activeStageId: number | null = null;
let activeTab: 'gating' | 'actions' | 'completion' = 'gating';
let blocklyWorkspace: Blockly.WorkspaceSvg;

// DOM element references (will be set inside setupControlProcedures)
let stageListEl: HTMLElement;
let editorHeaderEl: HTMLElement;
let generatedCodeEl: HTMLElement;
let TABS: {
    gating: HTMLElement;
    actions: HTMLElement;
    completion: HTMLElement;
};

/**
 * Sets up and renders the Control Procedures (Recipe Editor) component.
 * @param natsService The NatsSignalsService instance.
 * @param parentElement The HTML element where the control procedures should be rendered.
 */
export function setupControlProcedures(natsService: NatsSignalsService, parentElement: HTMLElement) {
    // Create an instance of MachineService. This will be used by the Blockly generated code
    // and potentially passed to custom blocks if needed.
    const _machineServiceInstance: IMachineService = new MachineService(fermentationModel);

    // Clear previous content and render the HTML structure for this module
    parentElement.innerHTML = `
        <div class="control-procedures-container">
            <div class="stage-list-panel">
                <div class="recipe-header">
                    <h3>${recipe.name}</h3>
                    <span class="status-active">ACTIVE</span>
                </div>
                <ul id="stage-list" class="stage-list">
                    <!-- Stages will be dynamically inserted here -->
                </ul>
            </div>

            <!-- Right Panel: The Editor -->
            <div id="editor-panel" class="editor-panel">
                <div id="editor-header">
                    <!-- Stage title will go here -->
                </div>
                <div class="editor-tabs">
                    <button id="tab-gating" class="tab-button active">Gating Criteria</button>
                    <button id="tab-actions" class="tab-button">Actions</button>
                    <button id="tab-completion" class="tab-button">Completion Criteria</button>
                </div>

                <!-- Blockly injection point -->
                <div id="blockly-container">
                    <div id="blockly-div" style="height: 400px; width: 100%;"></div>
                </div>

                <!-- Generated code output -->
                <div class="code-output">
                    <h4>Generated RxJS Code:</h4>
                    <pre><code id="generated-code"></code></pre>
                </div>
            </div>
        </div>
    `;

    // --- Get DOM Elements (scoped to parentElement) ---
    stageListEl = parentElement.querySelector('#stage-list') as HTMLElement;
    editorHeaderEl = parentElement.querySelector('#editor-header') as HTMLElement;
    generatedCodeEl = parentElement.querySelector('#generated-code') as HTMLElement;
    TABS = {
        gating: parentElement.querySelector('#tab-gating') as HTMLElement,
        actions: parentElement.querySelector('#tab-actions') as HTMLElement,
        completion: parentElement.querySelector('#tab-completion') as HTMLElement,
    };

    /** Renders the list of stages on the left panel */
    function renderStageList() {
        stageListEl.innerHTML = '';
        recipe.stages.forEach(stage => {
            const li = document.createElement('li');
            li.className = `stage-list-item ${stage.id === activeStageId ? 'selected' : ''}`;
            li.dataset.stageId = stage.id.toString();
            li.innerHTML = `
                <div class="stage-number stage-number-${stage.id}">${stage.id}</div>
                <div class="stage-details">
                    <h4>${stage.name}</h4>
                    <p>${stage.description}</p>
                </div>
            `;
            li.addEventListener('click', () => selectStage(stage.id));
            stageListEl.appendChild(li);
        });
    }

    /** Updates the editor panel when a stage is selected */
    function selectStage(stageId: number) {
        if (activeStageId === stageId) return;

        activeStageId = stageId;
        const stage = recipe.stages.find(s => s.id === stageId)!;

        // Update UI
        renderStageList();
        editorHeaderEl.innerHTML = `
            <h3>Stage ${stage.id}: ${stage.name}</h3>
            <p>Define the criteria and actions for the ${stage.name.toLowerCase()} stage.</p>
        `;

        // Load the blockly workspace for the currently active tab
        loadWorkspaceForActiveTab();
    }

    /** Loads the correct XML workspace into Blockly based on the active tab */
    function loadWorkspaceForActiveTab() {
        if (!activeStageId) return;
        const stage = recipe.stages.find(s => s.id === activeStageId)!;
        let xmlText = '';

        switch (activeTab) {
            case 'gating':
                xmlText = stage.gatingCriteria;
                break;
            case 'actions':
                xmlText = stage.actions;
                break;
            case 'completion':
                xmlText = stage.completionCriteria;
                break;
        }

        const xml = Blockly.utils.xml.textToDom(xmlText);
        Blockly.Xml.clearWorkspaceAndLoadFromXml(xml, blocklyWorkspace);
        updateCodeFromWorkspace();
    }

    /** Saves the current Blockly workspace back into our recipe state */
    function saveWorkspace() {
        if (!activeStageId) return;

        const stage = recipe.stages.find(s => s.id === activeStageId)!;
        const xml = Blockly.Xml.workspaceToDom(blocklyWorkspace);
        const xmlText = Blockly.utils.xml.domToText(xml);

        switch (activeTab) {
            case 'gating':
                stage.gatingCriteria = xmlText;
                break;
            case 'actions':
                stage.actions = xmlText;
                break;
            case 'completion':
                stage.completionCriteria = xmlText;
                break;
        }
    }

    /** Updates the code view whenever the workspace changes */
    function updateCodeFromWorkspace() {
        // Generate JavaScript code and display it.
        const code = javascriptGenerator.workspaceToCode(blocklyWorkspace);
        generatedCodeEl.textContent = code || "// Drag blocks into the editor to generate code";
    }

    /** Switches the active editor tab (Gating, Actions, etc.) */
    function selectTab(tabName: 'gating' | 'actions' | 'completion') {
        if (tabName === activeTab) return;

        // First, save the current workspace before switching
        saveWorkspace();

        activeTab = tabName;

        // Update tab button styles
        Object.values(TABS).forEach(btn => btn.classList.remove('active'));
        TABS[tabName].classList.add('active');

        // Load the new workspace
        loadWorkspaceForActiveTab();
    }

    // Inject Blockly into the correct div within the parentElement
    const blocklyDiv = parentElement.querySelector('#blockly-div') as HTMLElement;
    if (blocklyDiv) {
        blocklyWorkspace = configureBlockly(fermentationModel); // Pass fermentationModel
        // The previous configureBlockly already handles injecting into a div named 'blockly-div'
        // If it was taking a div element as an arg, it would be configureBlockly(blocklyDiv, fermentationModel);
        // Assuming configureBlockly uses document.getElementById('blockly-div') internally.
        // If configureBlockly needs the element directly, we'd need to modify configureBlockly in blockly-setup.ts
        // For now, assuming it finds the element by ID which is now within our rendered parentElement.
    } else {
        console.error("Blockly div not found in control procedures module.");
        return; // Exit if Blockly div is not available
    }

    // Add listener to update code and save state on any change
    blocklyWorkspace.addChangeListener((event: Blockly.Events.Abstract) => {
        // We only care about events that change the structure, not UI events like selection
        if (event.type === Blockly.Events.UI) return;
        updateCodeFromWorkspace();
        saveWorkspace();
    });

    // Set up tab click listeners
    TABS.gating.addEventListener('click', () => selectTab('gating'));
    TABS.actions.addEventListener('click', () => selectTab('actions'));
    TABS.completion.addEventListener('click', () => selectTab('completion'));

    // Initial render
    renderStageList();
    selectStage(3); // Start with Stage 3 selected as in the image
}
