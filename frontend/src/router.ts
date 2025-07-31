import { NatsSignalsService } from './nats-signals.service';
import {BioreactorApp} from "@/interface";

export function initializeRouter(natsService: NatsSignalsService, app:BioreactorApp) {
    // Simple client-side routing
    const routerOutlet = document.querySelector('.main-content') as HTMLElement;
    if (!routerOutlet) {
        console.error('Router outlet (.main-content) not found!');
        return;
    }

    // Define routes and their corresponding setup functions
    const routes: Record<string, () => Promise<any>> = {
        '#/physical-models': () => import('./app/object-model').then(m => m.setupObjectModel(natsService, routerOutlet)),
        '#/control-procedures': () => import('./recipe').then(m => m.setupControlProcedures(natsService, routerOutlet)),
        '#/batch-monitoring': () => import('./bioreactor-monitor').then(m => m.setupBioreactorMonitor(natsService, routerOutlet)),
        '#/configuration': () => {
            routerOutlet.innerHTML = '<h2>Configuration</h2><p>Configuration content goes here.</p>';
            return Promise.resolve();
        },
        '#/system': () => {
            routerOutlet.innerHTML = '<h2>System</h2><p>System content goes here.</p>';
            return Promise.resolve();
        },
    };

    const menuToggleCheckbox = document.getElementById('menu-toggle') as HTMLInputElement;
    const menuLinks = document.querySelector('.menu-links');

    function loadRoute(path: string) {
        routerOutlet.innerHTML = ''; // Clear previous content

        // Add 'active' class to current nav item
        menuLinks?.querySelectorAll('a').forEach(link => {
            if (link.getAttribute('routerLink') === path) {
                link.classList.add('active');
            } else {
                link.classList.remove('active');
            }
        });

        const handler = routes[path];
        if (handler) {
            handler().catch(err => console.error(`Failed to load route ${path}:`, err));
        } else {
            console.warn(`Route "${path}" not found. Redirecting to default.`);
            navigateTo('#/physical-models'); // Default to Physical Models page
        }
    }

    function navigateTo(path: string) {
        history.pushState(null, '', path);
        loadRoute(path);
        // Close menu if open
        if (menuToggleCheckbox) {
            menuToggleCheckbox.checked = false;
        }
    }

    // Attach click listeners to navigation links
    if (menuLinks) {
        menuLinks.querySelectorAll('.nav-item').forEach(link => {
            console.log("router link", link);
            link.addEventListener('click', (event) => {
                event.preventDefault();
                const path = link.getAttribute('routerLink');
                if (path) {
                    navigateTo(path);
                }
            });
        });
    }

    window.onhashchange = () => {
        const path = window.location.hash;
        loadRoute(path);
    };

    window.addEventListener('popstate', () => {
        loadRoute(window.location.hash);
    });

    // Initial route load: Default to '#/physical-models'
    const initialPath = window.location.hash || '#/physical-models';
    navigateTo(initialPath);
}
