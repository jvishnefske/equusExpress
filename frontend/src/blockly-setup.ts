import * as Blockly from 'blockly';
import { javascriptGenerator } from 'blockly/javascript';
import { PhysicalModel } from './models';

// -- Types for Import/Export --
interface ControlProcedure {
    id: string;
    name: string;
    description?: string;
    workspace: string; // XML representation of the Blockly workspace
    generatedCode: string; // Generated JavaScript code
    createdAt: string;
    updatedAt: string;
}

interface ImportExportOptions {
    baseUrl?: string; // Base URL for the API, defaults to current origin
    onSuccess?: (message: string) => void;
    onError?: (error: string) => void;
}

// -- Custom Block Definitions --

function defineSensorBlock(id: string, name: string) {
    Blockly.Blocks[id] = {
        init: function () {
            this.appendDummyInput().appendField(name); // e.g., "Temperature"
            this.setOutput(true, 'Number'); // This block returns a value
            this.setColour(230); // Blue color for sensors
            this.setTooltip(`Provides the latest value from the ${name} sensor.`);
            this.setHelpUrl('');
        },
    };

    // Code generator for the sensor block
    javascriptGenerator.forBlock[id] = function(_block) {
        // This generates code that would be used to get the sensor value
        // In a real execution engine, this would map to an RxJS observable stream
        const code = `machineService.getSensor$('${id}')`;
        return [code, javascriptGenerator.ORDER_ATOMIC];
    };
}

function defineActuatorBlock(id: string, name: string, params: { name: string, type: 'number' | 'string' }[]) {
    Blockly.Blocks[id] = {
        init: function () {
            const input = this.appendDummyInput().appendField(name); // e.g., "Set Agitation"
            params.forEach(param => {
                input.appendField(param.name);
                this.appendValueInput(param.name.toUpperCase()) // e.g., "RPM"
                    .setCheck(param.type === 'number' ? 'Number' : 'String');
            });
            this.setPreviousStatement(true, null); // Can be stacked
            this.setNextStatement(true, null);
            this.setColour(20); // Orange color for actuators
            this.setTooltip(`Activates the ${name} actuator.`);
        },
    };

    // Code generator for the actuator block
    javascriptGenerator.forBlock[id] = function(block) {
        const paramsObject = params.map(param => {
            const value = javascriptGenerator.valueToCode(block, param.name.toUpperCase(), javascriptGenerator.ORDER_ATOMIC) || 'null';
            return `'${param.name}': ${value}`;
        }).join(', ');

        const code = `machineService.triggerActuator('${id}', { ${paramsObject} });\n`;
        return code;
    };
}

// -- Import/Export Functions --

/**
 * Exports the current workspace to a REST endpoint
 */
export async function exportControlProcedure(
    workspace: Blockly.WorkspaceSvg,
    procedureId: string,
    name: string,
    description?: string,
    options: ImportExportOptions = {}
): Promise<void> {
    try {
        const baseUrl = options.baseUrl || window.location.origin;

        // Get the XML representation of the workspace
        const xml = Blockly.Xml.workspaceToDom(workspace);
        const xmlText = Blockly.Xml.domToText(xml);

        // Generate the JavaScript code
        const generatedCode = javascriptGenerator.workspaceToCode(workspace);

        // Prepare the control procedure data
        const controlProcedure: Omit<ControlProcedure, 'createdAt' | 'updatedAt'> = {
            id: procedureId,
            name,
            description,
            workspace: xmlText,
            generatedCode
        };

        // Send to REST endpoint
        const response = await fetch(`${baseUrl}/api/control_procedures/${procedureId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(controlProcedure)
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const result = await response.json();
        options.onSuccess?.(`Control procedure "${name}" exported successfully`);

    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
        options.onError?.(`Failed to export control procedure: ${errorMessage}`);
        throw error;
    }
}

/**
 * Imports a control procedure from a REST endpoint into the workspace
 */
export async function importControlProcedure(
    workspace: Blockly.WorkspaceSvg,
    procedureId: string,
    options: ImportExportOptions = {}
): Promise<ControlProcedure> {
    try {
        const baseUrl = options.baseUrl || window.location.origin;

        // Fetch from REST endpoint
        const response = await fetch(`${baseUrl}/api/control_procedures/${procedureId}`, {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
            }
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const controlProcedure: ControlProcedure = await response.json();

        // Clear the current workspace
        workspace.clear();

        // Load the XML into the workspace
        const xml = Blockly.utils.xml.textToDom(controlProcedure.workspace);
        Blockly.Xml.domToWorkspace(xml, workspace);

        options.onSuccess?.(`Control procedure "${controlProcedure.name}" imported successfully`);

        return controlProcedure;

    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
        options.onError?.(`Failed to import control procedure: ${errorMessage}`);
        throw error;
    }
}

/**
 * Lists all available control procedures from the REST endpoint
 */
export async function listControlProcedures(
    options: ImportExportOptions = {}
): Promise<ControlProcedure[]> {
    try {
        const baseUrl = options.baseUrl || window.location.origin;

        const response = await fetch(`${baseUrl}/api/control_procedures`, {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
            }
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const procedures: ControlProcedure[] = await response.json();
        return procedures;

    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
        options.onError?.(`Failed to list control procedures: ${errorMessage}`);
        throw error;
    }
}

/**
 * Deletes a control procedure from the REST endpoint
 */
export async function deleteControlProcedure(
    procedureId: string,
    options: ImportExportOptions = {}
): Promise<void> {
    try {
        const baseUrl = options.baseUrl || window.location.origin;

        const response = await fetch(`${baseUrl}/api/control_procedures/${procedureId}`, {
            method: 'DELETE'
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        options.onSuccess?.(`Control procedure deleted successfully`);

    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
        options.onError?.(`Failed to delete control procedure: ${errorMessage}`);
        throw error;
    }
}

/**
 * Enhanced workspace configuration with import/export toolbar buttons
 */
function addImportExportButtons(workspace: Blockly.WorkspaceSvg): void {
    // Create a custom toolbar for import/export
    const toolbarDiv = document.createElement('div');
    toolbarDiv.id = 'blockly-toolbar';
    toolbarDiv.style.cssText = `
        padding: 10px;
        background-color: #f5f5f5;
        border-bottom: 1px solid #ddd;
        display: flex;
        gap: 10px;
        align-items: center;
    `;

    // Export button
    const exportBtn = document.createElement('button');
    exportBtn.textContent = 'Export Procedure';
    exportBtn.style.cssText = `
        padding: 8px 16px;
        background-color: #4CAF50;
        color: white;
        border: none;
        border-radius: 4px;
        cursor: pointer;
    `;
    exportBtn.onclick = () => showExportDialog(workspace);

    // Import button
    const importBtn = document.createElement('button');
    importBtn.textContent = 'Import Procedure';
    importBtn.style.cssText = `
        padding: 8px 16px;
        background-color: #2196F3;
        color: white;
        border: none;
        border-radius: 4px;
        cursor: pointer;
    `;
    importBtn.onclick = () => showImportDialog(workspace);

    // List procedures button
    const listBtn = document.createElement('button');
    listBtn.textContent = 'List Procedures';
    listBtn.style.cssText = `
        padding: 8px 16px;
        background-color: #dd8800;
        color: white;
        border: none;
        border-radius: 4px;
        cursor: pointer;
    `;
    listBtn.onclick = () => showListDialog(workspace);

    toolbarDiv.appendChild(exportBtn);
    toolbarDiv.appendChild(importBtn);
    toolbarDiv.appendChild(listBtn);

    // Insert toolbar before the Blockly div
    const blocklyDiv = document.getElementById('blockly-div');
    if (blocklyDiv && blocklyDiv.parentNode) {
        blocklyDiv.parentNode.insertBefore(toolbarDiv, blocklyDiv);
    }
}

/**
 * Shows export dialog
 */
function showExportDialog(workspace: Blockly.WorkspaceSvg): void {
    const name = prompt('Enter procedure name:');
    if (!name) return;

    const description = prompt('Enter procedure description (optional):') || undefined;
    const id = prompt('Enter procedure ID:', name.toLowerCase().replace(/\s+/g, '_'));
    if (!id) return;

    exportControlProcedure(workspace, id, name, description, {
        onSuccess: (message) => alert(message),
        onError: (error) => alert(error)
    });
}

/**
 * Shows import dialog
 */
function showImportDialog(workspace: Blockly.WorkspaceSvg): void {
    const id = prompt('Enter procedure ID to import:');
    if (!id) return;

    importControlProcedure(workspace, id, {
        onSuccess: (message) => alert(message),
        onError: (error) => alert(error)
    });
}

/**
 * Shows list dialog
 */
async function showListDialog(workspace: Blockly.WorkspaceSvg): Promise<void> {
    try {
        const procedures = await listControlProcedures({
            onError: (error) => alert(error)
        });

        if (procedures.length === 0) {
            alert('No control procedures found.');
            return;
        }

        const procedureList = procedures
            .map(p => `${p.id}: ${p.name} (${p.updatedAt})`)
            .join('\n');

        const selectedId = prompt(`Available procedures:\n${procedureList}\n\nEnter ID to import:`);

        if (selectedId && procedures.find(p => p.id === selectedId)) {
            importControlProcedure(workspace, selectedId, {
                onSuccess: (message) => alert(message),
                onError: (error) => alert(error)
            });
        }
    } catch (error) {
        console.error('Error listing procedures:', error);
    }
}

/**
 * Configures Blockly with custom blocks and a dynamic toolbox.
 * @param model - The physical model of the machine.
 * @returns The configured Blockly workspace.
 */
export function configureBlockly(model: PhysicalModel): Blockly.WorkspaceSvg {
    // 1. Define custom blocks for all sensors and actuators in the model
    model.sensors.forEach(sensor => defineSensorBlock(sensor.id, sensor.name));
    model.actuators.forEach(actuator => defineActuatorBlock(actuator.id, actuator.name, actuator.params));

    // 2. Create the Toolbox JSON definition dynamically
    const toolbox = {
        kind: 'categoryToolbox',
        contents: [
            {
                kind: 'category',
                name: 'Logic',
                colour: 200, // Darker blue for general categories
                contents: [
                    { kind: 'block', type: 'controls_if' },
                    { kind: 'block', type: 'logic_compare' },
                    { kind: 'block', type: 'logic_operation' },
                    { kind: 'block', type: 'logic_negate' },
                    { kind: 'block', type: 'logic_boolean' },
                ],
            },
            {
                kind: 'category',
                name: 'Sensors',
                colour: 240, // Darker blue for sensors
                contents: model.sensors.map(s => ({ kind: 'block', type: s.id })),
            },
            {
                kind: 'category',
                name: 'Actuators',
                // colour: 0, // Red for actuators, generally darker
                contents: model.actuators.map(a => ({ kind: 'block', type: a.id })),
            },
            {
                kind: 'category',
                name: 'Math',
                // colour: 240, // Darker blue for math
                contents: [
                    { kind: 'block', type: 'math_number' },
                    { kind: 'block', type: 'math_arithmetic' },
                ],
            },
            {
                kind: 'category',
                name: 'Time',
                // colour: 170, // Darker green for time
                contents: [
                    // Future block: wait for duration
                    // Future block: check stability over time
                ],
            },
            {
                kind: 'category',
                name: 'Variables',
                custom: 'VARIABLE', // This tells Blockly to populate this category with variables dynamically
                colour: 330,
            },
        ],
    };

    // 3. Inject Blockly into the DOM
    const blocklyDiv = document.getElementById('blockly-div');
    if (!blocklyDiv) {
        throw new Error('Blockly div not found! Ensure an element with id="blockly-div" exists in your HTML.');
    }

    const workspace = Blockly.inject(blocklyDiv, {
        toolbox: toolbox,
        grid: { spacing: 20, length: 3, colour: '#ccc', snap: true },
        trashcan: true,
        // Add other configuration options as needed (e.g., zoom, scrollbars)
    });

    // Setup for dynamic variable creation if needed (often used with the 'VARIABLE' custom category)
    workspace.createVariableButtonHandler = function(button) {
        Blockly.Variables.createVariable(button.getTargetWorkspace(), undefined, undefined, 'variable');
    };

    // Add import/export functionality
    addImportExportButtons(workspace);

    return workspace;
}