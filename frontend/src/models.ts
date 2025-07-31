import { Observable } from 'rxjs';
import type * as Blockly from 'blockly';

// -- Data Model Interfaces --

export interface Sensor {
  id: string; // e.g., 'temp_bioreactor_1'
  name: string; // e.g., 'Temperature'
  units: string; // e.g., '°C'
}

export interface Actuator {
  id: string; // e.g., 'agitator_rpm'
  name: string; // e.g., 'Set Agitation'
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  params: { name: string, type: 'number' | 'string' }[];
}

export interface PhysicalModel {
  name: string;
  sensors: Sensor[];
  actuators: Actuator[];
}

// -- Stage and Recipe Interfaces --

// Define a type for the saved state of the blockly workspace (XML)
type BlocklyWorkspaceState = string;

export interface Stage {
  id: number;
  name: string;
  description: string;
  // Each criteria/action set is stored as a serialized Blockly workspace
  gatingCriteria: BlocklyWorkspaceState;
  actions: BlocklyWorkspaceState;
  completionCriteria: BlocklyWorkspaceState;
}

export interface Recipe {
  name: string;
  stages: Stage[];
}

// -- Service Interface --
// Defines the contract for our machine service
export interface IMachineService {
  getSensor$(sensorId: string): Observable<number>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  triggerActuator(actuatorId: string, params: Record<string, any>): void;
}
