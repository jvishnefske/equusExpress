import { Observable, timer, map, BehaviorSubject, scan, shareReplay, combineLatest } from 'rxjs';
import { IMachineService, PhysicalModel } from './models';

// The concrete physical model for our simulated machine
export const fermentationModel: PhysicalModel = {
    name: 'BioFlo 320',
    sensors: [
        { id: 'temperature', name: 'Temperature', units: '°C' },
        { id: 'ph_level', name: 'pH Level', units: '' },
        { id: 'dissolved_o2', name: 'Dissolved O₂', units: '%' },
        { id: 'od600', name: 'OD₆₀₀', units: '' },
        { id: 'contamination', name: 'Contamination', units: '' },
    ],
    actuators: [
        { id: 'set_agitation', name: 'Set Agitation', params: [{ name: 'rpm', type: 'number' }] },
        { id: 'set_temperature', name: 'Set Temperature', params: [{ name: 'celsius', type: 'number' }] },
        { id: 'open_inoculation_port', name: 'Open Inoculation Port', params: [] },
        { id: 'adjust_ph', name: 'Adjust pH', params: [{ name: 'direction', type: 'string' }] },
    ],
};

/**
 * A mock service that simulates a physical machine.
 * It provides live data streams (Observables) for sensors.
 */
export class MachineService implements IMachineService { // Export class for recipe.ts to use
    private model: PhysicalModel;
    private sensorStreams$: Map<string, Observable<number>> = new Map();
    
    // Agitation is a BehaviorSubject because it holds state that can be set by an actuator
    private agitation$ = new BehaviorSubject<number>(0);

    constructor(model: PhysicalModel) {
        this.model = model;
        this.initializeSensorStreams();
    }
    
    // Creates a hot, shared observable for each sensor in the model
    private initializeSensorStreams() {
        // Temperature: fluctuates around 37°C
        this.sensorStreams$.set('temperature', timer(0, 1500).pipe(
            map(() => 37 + Math.sin(Date.now() / 30000) * 0.5 + (Math.random() - 0.5) * 0.2),
            shareReplay(1)
        ));

        // pH: fluctuates around 7.0
        this.sensorStreams$.set('ph_level', timer(0, 2000).pipe(
            map(() => 7.0 + (Math.random() - 0.5) * 0.1),
            shareReplay(1)
        ));

        // Dissolved O2: fluctuates around 85%
        this.sensorStreams$.set('dissolved_o2', timer(0, 1000).pipe(
            map(() => 85 + (Math.random() - 0.2) * 5),
            shareReplay(1)
        ));
        
        // ADDED: dissolved_oxygen stream that combines base DO and agitation effect
        this.sensorStreams$.set('dissolved_oxygen', combineLatest([
            timer(0, 2500).pipe(map(() => 8.0 + Math.sin(Date.now() / 40000) * 0.8)), // Base DO
            this.agitation$ // Agitation affects DO slightly
        ]).pipe(
            map(([baseDo, agitationRpm]) => baseDo - (agitationRpm * 0.001)),
            shareReplay(1)
        ));

        // OD600: slowly grows over time
        this.sensorStreams$.set('od600', timer(0, 5000).pipe(
            scan(acc => acc + Math.random() * 0.001, 0.01),
            shareReplay(1)
        ));
        
        // Contamination: stays at 0
        this.sensorStreams$.set('contamination', new BehaviorSubject(0).asObservable());

        // Agitation is just the BehaviorSubject exposed as a simple Observable
        this.sensorStreams$.set('agitation', this.agitation$.asObservable());
    }
    
    /**
     * Public method to get a sensor's data stream.
     */
    public getSensor$(sensorId: string): Observable<number> {
        if (!this.sensorStreams$.has(sensorId)) {
            throw new Error(`Sensor with id '${sensorId}' not found.`);
        }
        return this.sensorStreams$.get(sensorId)!;
    }

    /**
     * Simulates triggering a machine actuator.
     */
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    public triggerActuator(actuatorId: string, params: Record<string, any>): void { 
        console.log(`%c[ACTUATOR] Triggered: ${actuatorId} with params:`, 'color: orange', params);
        
        if (actuatorId === 'set_agitation') {
            this.agitation$.next(params.rpm);
            console.log(`%c[MACHINE] Agitation set to ${params.rpm} RPM`, 'color: cyan');
        }
        // In a real app, this would send a command to the machine control system.
        // For now, it just logs and updates internal state where applicable.
    }
}

// Export a singleton instance of the service
export const machineService = new MachineService(fermentationModel);
