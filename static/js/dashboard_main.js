document.addEventListener('DOMContentLoaded', async function() {
    if (window.dashboardInitialized) {
        console.log('[DEBUG] Dashboard already initialized, skipping...');
        return;
    }
    window.dashboardInitialized = true;

    while (typeof window.Auth === 'undefined') {
        await new Promise(resolve => setTimeout(resolve, 100));
    }

    if (!window.Auth.isAuthenticated()) {
        console.warn('User not authenticated, redirecting to login page...');
        window.location.href = '/';
        return;
    }

    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            console.log('[DEBUG] Logout button clicked');
            window.Auth.logout();
        });
    }

    setTimeout(() => {
        AOS.init({
            once: true,
            disable: window.innerWidth < 768
        });
    }, 100);
    
    initParticles();
    
    const clickableElements = document.querySelectorAll('.neo-btn, .neo-btn-primary, .tab-button, button');
    clickableElements.forEach(element => {
        element.classList.add('ripple');
    });
    
    const tabButtons = document.querySelectorAll('.tab-button');
    tabButtons.forEach(tab => {
        const newTab = tab.cloneNode(true);
        tab.parentNode.replaceChild(newTab, tab);
        
        newTab.addEventListener('click', function() {
            tabButtons.forEach(t => t.classList.remove('tab-active'));
            this.classList.add('tab-active');
        });
    });
    
    const commandButtons = document.querySelectorAll('[data-command]');
    commandButtons.forEach(button => {
        const newButton = button.cloneNode(true);
        button.parentNode.replaceChild(newButton, button);
        
        newButton.addEventListener('click', function() {
            this.classList.toggle('active');
            
            const command = this.getAttribute('data-command');
            console.log(`Command selected: ${command}`);
        });
    });
    
    const selectionButtons = document.querySelectorAll('#selectAllBtn, #selectActiveBtn, #selectNoneBtn');
    selectionButtons.forEach(button => {
        const newButton = button.cloneNode(true);
        button.parentNode.replaceChild(newButton, button);
        
        newButton.addEventListener('click', function() {
            selectionButtons.forEach(b => {
                if (b !== this) b.classList.remove('active');
            });
            this.classList.toggle('active');
        });
    });
    
    const fileTypeButtons = document.querySelectorAll('.file-type-btn');
    fileTypeButtons.forEach(button => {
        const newButton = button.cloneNode(true);
        button.parentNode.replaceChild(newButton, button);
        
        newButton.addEventListener('click', function() {
            fileTypeButtons.forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');
            document.getElementById('fileType').value = this.getAttribute('data-type');
        });
    });
    
    document.querySelectorAll('.fa-circle.text-green-400').forEach(icon => {
        const parent = icon.parentElement;
        const statusDot = document.createElement('span');
        statusDot.className = 'status-dot active';
        parent.replaceChild(statusDot, icon);
    });
    
    document.querySelectorAll('.fa-circle.text-yellow-400').forEach(icon => {
        const parent = icon.parentElement;
        const statusDot = document.createElement('span');
        statusDot.className = 'status-dot idle';
        parent.replaceChild(statusDot, icon);
    });
    
    document.querySelectorAll('.fa-circle.text-red-400').forEach(icon => {
        const parent = icon.parentElement;
        const statusDot = document.createElement('span');
        statusDot.className = 'status-dot dead';
        parent.replaceChild(statusDot, icon);
    });
});

function initParticles() {
    const particlesContainer = document.querySelector('.particles-container');
    const particleCount = 30;
    
    for (let i = 0; i < particleCount; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        
        const posX = Math.random() * 100;
        const posY = Math.random() * 100;
        
        const size = Math.random() * 6 + 1;
        
        const opacity = Math.random() * 0.5 + 0.1;
        
        const duration = Math.random() * 20 + 10;
        
        particle.style.left = `${posX}%`;
        particle.style.top = `${posY}%`;
        particle.style.width = `${size}px`;
        particle.style.height = `${size}px`;
        particle.style.opacity = opacity;
        particle.style.animationDuration = `${duration}s`;
        
        particlesContainer.appendChild(particle);
    }
}

window.openUploadModal = function() {
    console.log("Opening upload modal");
    const fileUploadModal = document.getElementById('file-upload-modal');
    if (!fileUploadModal) {
        console.error("File upload modal not found");
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
    
    const securityWarning = document.getElementById('browser-security-warning');
    if (securityWarning) securityWarning.classList.add('hidden');
    
    const directUrlInput = document.getElementById('direct-file-url');
    if (directUrlInput) directUrlInput.value = '';
    
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
    console.log("Closing upload modal");
    const fileUploadModal = document.getElementById('file-upload-modal');
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
    console.log("Updating drop zone with file info:", file.name);
    const dropZone = document.getElementById('drop-zone');
    if (!dropZone) return;
    
    const icon = dropZone.querySelector('i');
    const mainText = dropZone.querySelector('p:first-of-type');
    const subText = dropZone.querySelector('p:last-of-type');
    
    dropZone.classList.add('border-primary');
    dropZone.classList.add('bg-primary/5');
    
    if (icon) icon.classList.add('text-primary');
    
    if (mainText) {
        mainText.textContent = file.name;
        mainText.classList.add('font-medium');
    }
    
    if (subText) {
        const fileSize = formatFileSize(file.size);
        const fileType = file.type || 'Unknown type';
        subText.textContent = `${fileType} • ${fileSize}`;
    }
};

window.uploadSelectedFile = async function() {
    console.log("Starting file upload process");
    const fileUploadInput = document.getElementById('file-upload-input');
    const uploadProgress = document.getElementById('upload-progress');
    const uploadSuccess = document.getElementById('upload-success');
    const uploadError = document.getElementById('upload-error');

    if (uploadSuccess) uploadSuccess.classList.add('hidden');
    if (uploadError) uploadError.classList.add('hidden');

    if (!fileUploadInput || !fileUploadInput.files || fileUploadInput.files.length === 0) {
        showUploadError('Please select a file to upload');
        return;
    }

    const file = fileUploadInput.files[0];
    console.log('Uploading file:', file.name, 'Type:', file.type);

    if (file.size > 100 * 1024 * 1024) { 
        showUploadError('File size exceeds 100MB limit');
        return;
    }

    const ext = file.name.toLowerCase().split('.').pop();
    if (ext !== 'bat') {
        showUploadError('Only .bat files are supported');
        return;
    }

    if (uploadProgress) uploadProgress.classList.remove('hidden');

    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch('/upload', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error(`Upload failed: ${response.statusText}`);
        }

        const result = await response.json();
        console.log('Upload successful:', result);

        if (uploadSuccess) {
            uploadSuccess.textContent = 'File uploaded successfully!';
            uploadSuccess.classList.remove('hidden');
        }

        fileUploadInput.value = '';

        if (document.getElementById('executeAfterUpload').checked) {
            executeUploadedFile(result.url, result.type);
        }

    } catch (error) {
        console.error('Upload error:', error);
        showUploadError(error.message);
    } finally {
        if (uploadProgress) uploadProgress.classList.add('hidden');
    }
};

function executeUploadedFile(fileUrl, fileType) {
    console.log(`Executing uploaded file: ${fileUrl} (${fileType})`);
    
    const executeInMemory = document.getElementById('executeInMemory').checked;
    
    let command;
    if (executeInMemory) {
        command = `execute:bat:${fileUrl}`;
    } else {
        const dropLocation = document.getElementById('dropLocation').value.trim() || '%TEMP%';
        command = `drop:bat:${fileUrl}:${dropLocation}`;
    }

    const selectedClients = getSelectedClients();
    
    if (selectedClients.length > 0) {
        console.log(`Executing on ${selectedClients.length} clients:`, command);
        window.sendCommandToMultipleClients(selectedClients, command);
    } else {
        console.log('No clients selected');
        alert('Please select at least one client before executing');
    }
}

function getSelectedClients() {
    const checkboxes = document.querySelectorAll('.client-checkbox:checked');
    return Array.from(checkboxes).map(checkbox => checkbox.getAttribute('data-client-id'));
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatTime(seconds) {
    if (seconds < 60) {
        return `${Math.round(seconds)}s`;
    } else {
        const minutes = Math.floor(seconds / 60);
        const remainingSeconds = Math.round(seconds % 60);
        return `${minutes}m ${remainingSeconds}s`;
    }
}

function showUploadError(message) {
    console.error("Upload error:", message);
    
    const uploadProgress = document.getElementById('upload-progress');
    if (uploadProgress) uploadProgress.classList.add('hidden');
    
    const uploadError = document.getElementById('upload-error');
    const errorMessage = document.getElementById('error-message');
    
    if (uploadError) uploadError.classList.remove('hidden');
    if (errorMessage) errorMessage.textContent = message;
}

document.addEventListener('DOMContentLoaded', function() {
    console.log("DOM Content Loaded - Setting up handlers");
    
    const clearConsoleBtn = document.getElementById('clearConsoleBtn');
    if (clearConsoleBtn) {
        clearConsoleBtn.addEventListener('click', function() {
            const consoleOutput = document.getElementById('console-output');
            if (consoleOutput) {
                consoleOutput.innerHTML = '';
                console.log("Console cleared");
            }
        });
    }
    
    const fileUploadModal = document.getElementById('file-upload-modal');
    const fileUploadClose = document.getElementById('file-upload-close');
    const uploadCancel = document.getElementById('upload-cancel');
    const dropZone = document.getElementById('drop-zone');
    const fileUploadInput = document.getElementById('file-upload-input');
    const uploadSubmit = document.getElementById('upload-submit');
    
    console.log('Setting up file upload modal handlers', {
        modal: !!fileUploadModal,
        closeBtn: !!fileUploadClose,
        cancelBtn: !!uploadCancel,
        dropZone: !!dropZone,
        fileInput: !!fileUploadInput,
        submitBtn: !!uploadSubmit
    });
    
    if (fileUploadClose) {
        fileUploadClose.addEventListener('click', function(e) {
            e.preventDefault();
            console.log("Close button clicked");
            window.closeUploadModal();
        });
    }
    
    if (uploadCancel) {
        uploadCancel.addEventListener('click', function(e) {
            e.preventDefault();
            console.log("Cancel button clicked");
            window.closeUploadModal();
        });
    }
    
    if (fileUploadModal) {
        fileUploadModal.addEventListener('click', function(e) {
            if (e.target === fileUploadModal) {
                console.log("Modal background clicked");
                window.closeUploadModal();
            }
        });
    }
    
    if (dropZone) {
        dropZone.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            console.log('Drop zone clicked');
            if (fileUploadInput) {
                console.log('Triggering file input click');
                fileUploadInput.click();
            }
        });
        
        dropZone.addEventListener('dragover', function(e) {
            e.preventDefault();
            e.stopPropagation();
            console.log('File drag over');
            dropZone.classList.add('border-primary');
            dropZone.classList.add('bg-primary/5');
        });
        
        dropZone.addEventListener('dragleave', function(e) {
            e.preventDefault();
            e.stopPropagation();
            console.log('File drag leave');
            if (!fileUploadInput || !fileUploadInput.files || !fileUploadInput.files.length) {
                dropZone.classList.remove('border-primary');
                dropZone.classList.remove('bg-primary/5');
            }
        });
        
        dropZone.addEventListener('drop', function(e) {
            e.preventDefault();
            e.stopPropagation();
            console.log('File dropped');
            if (e.dataTransfer.files.length > 0 && fileUploadInput) {
                fileUploadInput.files = e.dataTransfer.files;
                const file = e.dataTransfer.files[0];
                console.log("File received:", file.name, "Type:", file.type);
                
                checkAndShowSecurityWarning(file.name);
                
                window.updateDropZoneWithFileInfo(file);
            }
        });
    }
    
    if (fileUploadInput) {
        fileUploadInput.addEventListener('change', function(e) {
            console.log('File input changed');
            if (fileUploadInput.files && fileUploadInput.files.length > 0) {
                const file = fileUploadInput.files[0];
                console.log("File selected:", file.name, "Type:", file.type);
                
                checkAndShowSecurityWarning(file.name);
                
                window.updateDropZoneWithFileInfo(file);
            }
        });
    }
    
    if (uploadSubmit) {
        uploadSubmit.addEventListener('click', function(e) {
            e.preventDefault();
            console.log('Upload button clicked');
            window.uploadSelectedFile();
        });
    }
    
    const useDirectUrlBtn = document.getElementById('use-direct-url');
    const directFileUrlInput = document.getElementById('direct-file-url');
    if (useDirectUrlBtn && directFileUrlInput) {
        useDirectUrlBtn.addEventListener('click', function(e) {
            e.preventDefault();
            const directUrl = directFileUrlInput.value.trim();
            console.log('Direct URL button clicked:', directUrl);
            
            if (!directUrl) {
                alert('Please enter a direct file URL');
                return;
            }
            
            const fileUrlInput = document.getElementById('fileUrl');
            if (fileUrlInput) {
                fileUrlInput.value = directUrl;
                console.log('Updated main fileUrl field with:', directUrl);
            }
            
            const fileTypeInput = document.getElementById('fileType');
            if (fileTypeInput) {
                const detectedType = detectFileTypeFromUrl(directUrl);
                if (detectedType) {
                    fileTypeInput.value = detectedType;
                    console.log('Detected and set file type to:', detectedType);
                    
                    const fileTypeButtons = document.querySelectorAll('.file-type-btn');
                    fileTypeButtons.forEach(button => {
                        if (button.getAttribute('data-type') === detectedType) {
                            fileTypeButtons.forEach(btn => btn.classList.remove('active'));
                            button.classList.add('active');
                        }
                    });
                }
            }
            
            simulateDirectUrlUploadSuccess();
        });
    }
    
    const dropFileBtn = document.getElementById('dropFileBtn');
    if (dropFileBtn) {
        const newBtn = dropFileBtn.cloneNode(true);
        dropFileBtn.parentNode.replaceChild(newBtn, dropFileBtn);
        
        newBtn.addEventListener('click', function(e) {
            e.preventDefault();
            console.log('Drop & Run button clicked');
            window.openUploadModal();
        });
    }
});

function checkAndShowSecurityWarning(filename) {
    if (!filename) return;
    
    const fileExtension = '.' + filename.split('.').pop().toLowerCase();
    
    const warningElement = document.getElementById('browser-security-warning');
    if (warningElement) {
        if (fileExtension === '.bat') {
            console.log("Batch file detected, showing security warning");
            warningElement.classList.remove('hidden');
            
            const directUrlInput = document.getElementById('direct-file-url');
            if (directUrlInput) {
                setTimeout(() => directUrlInput.focus(), 200);
            }
        } else {
            warningElement.classList.add('hidden');
        }
    }
}

function detectFileTypeFromUrl(url) {
    if (!url) return null;
    
    const urlParts = url.split('/');
    const filename = urlParts[urlParts.length - 1].split('?')[0]; 
    
    const parts = filename.split('.');
    if (parts.length < 2) return null;
    
    const extension = parts[parts.length - 1].toLowerCase();
    
    return extension === 'bat' ? 'bat' : null;
}

async function generateKey(authToken) {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(authToken.slice(0, 32));
    return await crypto.subtle.importKey(
        "raw",
        keyData,
        { name: "AES-GCM" },
        false,
        ["encrypt"]
    );
}

async function encryptCommand(command, authToken) {
    try {
        const key = await generateKey(authToken);
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
        return null;
    }
}

window.sendCommandToMultipleClients = async function(clientIds, command) {
    console.log(`Sending command to ${clientIds.length} clients:`, command);
    
    for (const clientId of clientIds) {
        try {
            const tokenResponse = await fetch(`/api/client/${clientId}/token`);
            if (!tokenResponse.ok) {
                console.error(`Failed to get token for client ${clientId}`);
                continue;
            }
            const { token } = await tokenResponse.json();
            
            const encryptedCommand = await encryptCommand(command, token);
            if (!encryptedCommand) {
                console.error(`Failed to encrypt command for client ${clientId}`);
                continue;
            }

            const response = await fetch('/api/command', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    clientId: clientId,
                    command: encryptedCommand,
                    encrypted: true
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();
            console.log(`Command sent successfully to ${clientId}. Task ID: ${result.taskId}`);
            
            updateCommandStatus(clientId, 'Command sent successfully');
        } catch (error) {
            console.error(`Error sending command to ${clientId}:`, error);
            updateCommandStatus(clientId, 'Failed to send command');
        }
    }
};