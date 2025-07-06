// Global state management for multi-session support
const AppState = {
    sender: {
        senderId: null,
        handshakeComplete: false,
        fileUploaded: false,
        encrypted: false,
        transmitted: false,
        receiverPublicKey: null
    },
    receiver: {
        keysReady: false,
        handshakeReceived: false,
        packageReceived: false,
        verified: false,
        receivedFiles: []
    },
    server: {
        activeSessions: 0,
        receiverKeyReady: false
    }
};

// Utility functions
function logActivity(message, type = 'info', containerId = 'activityLog') {
    const logContainer = document.getElementById(containerId);
    if (!logContainer) return;
    
    const timestamp = new Date().toLocaleTimeString();
    const logEntry = document.createElement('div');
    logEntry.className = `log-entry ${type}`;
    logEntry.innerHTML = `
        <small class="text-muted">${timestamp}</small><br>
        <span>${message}</span>
    `;
    
    logContainer.appendChild(logEntry);
    logContainer.scrollTop = logContainer.scrollHeight;
}

function updateStatusStep(stepId, status, message = '') {
    const step = document.getElementById(stepId);
    if (!step) return;
    
    step.className = `status-step ${status}`;
    const statusText = step.querySelector('small');
    if (statusText && message) {
        statusText.textContent = message;
    }
}

function showAlert(containerId, message, type = 'info') {
    const container = document.getElementById(containerId);
    if (!container) return;
    
    container.innerHTML = `
        <div class="alert alert-${type} alert-dismissible fade show" role="alert">
            <i class="fas fa-${getAlertIcon(type)} me-2"></i>
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `;
}

function getAlertIcon(type) {
    const icons = {
        'success': 'check-circle',
        'danger': 'exclamation-triangle',
        'warning': 'exclamation-circle',
        'info': 'info-circle'
    };
    return icons[type] || 'info-circle';
}

// API Helper
async function apiRequest(url, options = {}) {
    try {
        const response = await fetch(url, {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || 'API request failed');
        }
        
        return data;
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

// Sender functionality
function initializeSender() {
    const handshakeBtn = document.getElementById('handshakeBtn');
    const uploadForm = document.getElementById('uploadForm');
    const encryptBtn = document.getElementById('encryptBtn');
    const transmitBtn = document.getElementById('transmitBtn');
    
    // Handshake handler
    if (handshakeBtn) {
        handshakeBtn.addEventListener('click', async () => {
            try {
                handshakeBtn.disabled = true;
                handshakeBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Connecting...';
                updateStatusStep('step1', 'active', 'Initiating...');
                
                const response = await apiRequest('/api/sender/handshake', {
                    method: 'POST'
                });
                
                // Store sender ID and receiver public key
                AppState.sender.senderId = response.sender_id;
                AppState.sender.receiverPublicKey = response.receiver_public_key;
                AppState.sender.handshakeComplete = true;
                
                // Auto-fill receiver public key
                const publicKeyField = document.getElementById('receiverPublicKey');
                if (publicKeyField) {
                    publicKeyField.value = response.receiver_public_key;
                }
                
                logActivity(`Handshake successful! Sender ID: ${response.sender_id.substring(0, 8)}...`, 'success');
                updateStatusStep('step1', 'complete', 'Complete');
                
                // Enable file upload
                document.getElementById('uploadBtn').disabled = false;
                
                showAlert('handshakeStatus', 
                    `Connected to receiver! Sender ID: ${response.sender_id.substring(0, 8)}...<br>` +
                    `Receiver public key automatically loaded.`, 'success');
                
            } catch (error) {
                logActivity('Handshake failed: ' + error.message, 'error');
                updateStatusStep('step1', 'error', 'Failed');
                showAlert('handshakeStatus', 'Handshake failed: ' + error.message, 'danger');
            } finally {
                handshakeBtn.innerHTML = '<i class="fas fa-handshake me-2"></i>Start Handshake';
                handshakeBtn.disabled = false;
            }
        });
    }
    
    // File upload handler
    if (uploadForm) {
        uploadForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const uploadBtn = document.getElementById('uploadBtn');
            const formData = new FormData(uploadForm);
            
            try {
                uploadBtn.disabled = true;
                uploadBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Uploading...';
                updateStatusStep('step2', 'active', 'Uploading...');
                
                const response = await fetch('/api/sender/upload', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                
                if (!response.ok) {
                    throw new Error(data.message);
                }
                
                logActivity(`File uploaded: ${data.filename}`, 'success');
                updateStatusStep('step2', 'complete', 'Complete');
                AppState.sender.fileUploaded = true;
                
                // Enable encryption step
                document.getElementById('encryptBtn').disabled = false;
                
                showAlert('uploadStatus', 'File uploaded successfully! Enter receiver\'s public key to proceed.', 'success');
                
            } catch (error) {
                logActivity('Upload failed: ' + error.message, 'error');
                updateStatusStep('step2', 'error', 'Failed');
                showAlert('uploadStatus', 'Upload failed: ' + error.message, 'danger');
            } finally {
                uploadBtn.innerHTML = '<i class="fas fa-upload me-2"></i>Upload File';
                uploadBtn.disabled = false;
            }
        });
    }
    
    // Encryption handler
    if (encryptBtn) {
        encryptBtn.addEventListener('click', async () => {
            const publicKeyInput = document.getElementById('receiverPublicKey');
            const publicKey = publicKeyInput.value.trim();
            
            if (!publicKey) {
                showAlert('encryptStatus', 'Please enter the receiver\'s public key.', 'warning');
                return;
            }
            
            try {
                encryptBtn.disabled = true;
                encryptBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Encrypting...';
                updateStatusStep('step3', 'active', 'Encrypting...');
                
                const response = await apiRequest('/api/sender/send', {
                    method: 'POST',
                    body: JSON.stringify({
                        receiver_public_key: publicKey
                    })
                });
                
                logActivity('File encrypted and signed successfully', 'success');
                updateStatusStep('step3', 'complete', 'Complete');
                AppState.sender.encrypted = true;
                AppState.sender.receiverPublicKey = publicKey;
                
                // Enable transmission
                document.getElementById('transmitBtn').disabled = false;
                
                showAlert('encryptStatus', 'File encrypted and signed! Ready for transmission.', 'success');
                
            } catch (error) {
                logActivity('Encryption failed: ' + error.message, 'error');
                updateStatusStep('step3', 'error', 'Failed');
                showAlert('encryptStatus', 'Encryption failed: ' + error.message, 'danger');
            } finally {
                encryptBtn.innerHTML = '<i class="fas fa-lock me-2"></i>Encrypt & Sign File';
                encryptBtn.disabled = false;
            }
        });
    }
    
    // Transmission handler
    if (transmitBtn) {
        transmitBtn.addEventListener('click', async () => {
            try {
                transmitBtn.disabled = true;
                transmitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Transmitting...';
                updateStatusStep('step4', 'active', 'Transmitting...');
                
                const response = await apiRequest('/api/sender/transmit', {
                    method: 'POST'
                });
                
                logActivity('Package transmitted successfully', 'success');
                updateStatusStep('step4', 'complete', 'Complete');
                AppState.sender.transmitted = true;
                
                showAlert('transmitStatus', 
                    `Package transmitted successfully! Size: ${response.package_size} bytes<br>` +
                    `<small>Share this package with the receiver for verification.</small>`, 'success');
                
                // Show the package for copying
                setTimeout(() => {
                    const packageJson = JSON.stringify(response.package, null, 2);
                    showAlert('transmitStatus', 
                        `<strong>Secure Package (copy this to receiver):</strong><br>` +
                        `<textarea class="form-control mt-2" rows="8" readonly>${packageJson}</textarea>` +
                        `<button class="btn btn-sm btn-primary mt-2" onclick="copyPackageToClipboard('${packageJson.replace(/"/g, '&quot;')}')">` +
                        `<i class="fas fa-copy me-1"></i>Copy Package</button>`, 'info');
                }, 1000);
                
            } catch (error) {
                logActivity('Transmission failed: ' + error.message, 'error');
                updateStatusStep('step4', 'error', 'Failed');
                showAlert('transmitStatus', 'Transmission failed: ' + error.message, 'danger');
            } finally {
                transmitBtn.innerHTML = '<i class="fas fa-paper-plane me-2"></i>Transmit Package';
                transmitBtn.disabled = false;
            }
        });
    }
}

// Receiver functionality
function initializeReceiver() {
    const copyKeyBtn = document.getElementById('copyKeyBtn');
    const refreshKeyBtn = document.getElementById('refreshKeyBtn');
    const respondHandshakeBtn = document.getElementById('respondHandshakeBtn');
    const receiveBtn = document.getElementById('receiveBtn');
    const refreshSessionsBtn = document.getElementById('refreshSessionsBtn');
    
    // Load public key on initialization
    loadPublicKey();
    
    // Load session monitor
    loadSessionMonitor();
    
    // Auto-refresh sessions every 30 seconds
    setInterval(loadSessionMonitor, 30000);
    
    // Copy key handler
    if (copyKeyBtn) {
        copyKeyBtn.addEventListener('click', () => {
            const publicKeyDisplay = document.getElementById('publicKeyDisplay');
            if (publicKeyDisplay) {
                navigator.clipboard.writeText(publicKeyDisplay.value).then(() => {
                    logActivity('Public key copied to clipboard', 'success', 'receiverActivityLog');
                    copyKeyBtn.innerHTML = '<i class="fas fa-check me-2"></i>Copied!';
                    setTimeout(() => {
                        copyKeyBtn.innerHTML = '<i class="fas fa-copy me-2"></i>Copy Public Key';
                    }, 2000);
                });
            }
        });
    }
    
    // Refresh key handler
    if (refreshKeyBtn) {
        refreshKeyBtn.addEventListener('click', () => {
            loadPublicKey();
            logActivity('New RSA key pair generated', 'info', 'receiverActivityLog');
        });
    }
    
    // Handshake response handler
    if (respondHandshakeBtn) {
        respondHandshakeBtn.addEventListener('click', async () => {
            try {
                respondHandshakeBtn.disabled = true;
                respondHandshakeBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Responding...';
                
                const response = await apiRequest('/api/receiver/handshake', {
                    method: 'POST',
                    body: JSON.stringify({
                        message: 'Hello!'
                    })
                });
                
                logActivity('Handshake response sent: ' + response.message, 'success', 'receiverActivityLog');
                updateStatusStep('recv-step2', 'complete', 'Complete');
                updateBadgeStatus('handshakeStatus', 'Complete', 'success');
                
                showAlert('handshakeResponseStatus', 'Handshake completed! Ready to receive packages.', 'success');
                
            } catch (error) {
                logActivity('Handshake response failed: ' + error.message, 'error', 'receiverActivityLog');
                showAlert('handshakeResponseStatus', 'Handshake failed: ' + error.message, 'danger');
            } finally {
                respondHandshakeBtn.innerHTML = '<i class="fas fa-handshake me-2"></i>Send "Ready!" Response';
                respondHandshakeBtn.disabled = false;
            }
        });
    }
    
    // Package reception handler
    if (receiveBtn) {
        receiveBtn.addEventListener('click', async () => {
            const packageInput = document.getElementById('packageInput');
            const packageData = packageInput.value.trim();
            
            if (!packageData) {
                showAlert('receptionResult', 'Please paste the secure package JSON.', 'warning');
                return;
            }
            
            try {
                receiveBtn.disabled = true;
                receiveBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Verifying...';
                updateStatusStep('recv-step3', 'active', 'Verifying...');
                
                let parsedPackage;
                try {
                    parsedPackage = JSON.parse(packageData);
                } catch (parseError) {
                    throw new Error('Invalid JSON format');
                }
                
                const response = await apiRequest('/api/receiver/receive', {
                    method: 'POST',
                    body: JSON.stringify({
                        package: parsedPackage
                    })
                });
                
                if (response.status === 'success') {
                    logActivity(`File received: ${response.filename}`, 'success', 'receiverActivityLog');
                    updateStatusStep('recv-step3', 'complete', 'Verified');
                    updateBadgeStatus('integrityStatus', 'Verified', 'success');
                    updateBadgeStatus('signatureStatus', 'Valid', 'success');
                    
                    // Update verification results
                    displayVerificationResults(response);
                    
                    // Add to received files with sender info
                    addReceivedFile(response.filename, response.metadata, {
                        sender_id: response.sender_id,
                        received_at: response.received_at,
                        integrity: response.integrity
                    });
                    
                    showAlert('receptionResult', response.message, 'success');
                    
                } else {
                    throw new Error(response.message);
                }
                
            } catch (error) {
                logActivity('Package verification failed: ' + error.message, 'error', 'receiverActivityLog');
                updateStatusStep('recv-step3', 'error', 'Failed');
                updateBadgeStatus('integrityStatus', 'Failed', 'danger');
                updateBadgeStatus('signatureStatus', 'Invalid', 'danger');
                showAlert('receptionResult', error.message, 'danger');
            } finally {
                receiveBtn.innerHTML = '<i class="fas fa-download me-2"></i>Receive & Verify Package';
                receiveBtn.disabled = false;
            }
        });
    }
    
    // Session monitoring handler
    if (refreshSessionsBtn) {
        refreshSessionsBtn.addEventListener('click', () => {
            loadSessionMonitor();
        });
    }
}

// Helper functions for receiver
async function loadPublicKey() {
    try {
        const response = await apiRequest('/api/receiver/public-key');
        const publicKeyDisplay = document.getElementById('publicKeyDisplay');
        if (publicKeyDisplay) {
            publicKeyDisplay.value = response.public_key;
        }
        updateStatusStep('recv-step1', 'complete', 'Ready');
        updateBadgeStatus('keyStatus', 'Ready', 'success');
        AppState.receiver.keysReady = true;
    } catch (error) {
        logActivity('Failed to load public key: ' + error.message, 'error', 'receiverActivityLog');
        updateStatusStep('recv-step1', 'error', 'Failed');
        updateBadgeStatus('keyStatus', 'Error', 'danger');
    }
}

function updateBadgeStatus(badgeId, text, type) {
    const badge = document.getElementById(badgeId);
    if (badge) {
        badge.textContent = text;
        badge.className = `badge bg-${type}`;
    }
}

function displayVerificationResults(response) {
    const resultsContainer = document.getElementById('verificationResults');
    if (!resultsContainer) return;
    
    resultsContainer.innerHTML = `
        <div class="row">
            <div class="col-md-6">
                <h6 class="text-success">✓ Verification Successful</h6>
                <ul class="list-unstyled">
                    <li><strong>File:</strong> ${response.filename}</li>
                    <li><strong>Original Name:</strong> ${response.metadata.filename}</li>
                    <li><strong>Copyright:</strong> ${response.metadata.copyright || 'Not specified'}</li>
                </ul>
            </div>
            <div class="col-md-6">
                <h6 class="text-info">Security Checks</h6>
                <ul class="list-unstyled">
                    <li><i class="fas fa-check text-success me-2"></i>Hash Integrity: Valid</li>
                    <li><i class="fas fa-check text-success me-2"></i>Digital Signature: Valid</li>
                    <li><i class="fas fa-check text-success me-2"></i>Decryption: Successful</li>
                    <li><i class="fas fa-check text-success me-2"></i>Metadata: Verified</li>
                </ul>
            </div>
        </div>
    `;
}

function addReceivedFile(filename, metadata) {
    const filesContainer = document.getElementById('receivedFiles');
    if (!filesContainer) return;
    
    if (filesContainer.innerHTML.includes('No files received')) {
        filesContainer.innerHTML = '';
    }
    
    const fileEntry = document.createElement('div');
    fileEntry.className = 'mb-2 p-2 border rounded';
    fileEntry.innerHTML = `
        <div class="d-flex justify-content-between align-items-center">
            <div>
                <i class="fas fa-music text-primary me-2"></i>
                <strong>${filename}</strong>
            </div>
            <small class="text-muted">${new Date().toLocaleTimeString()}</small>
        </div>
        <small class="text-muted">Original: ${metadata.filename}</small>
    `;
    
    filesContainer.appendChild(fileEntry);
}

// Host management functions
async function connectToHost(hostId) {
    try {
        const response = await apiRequest('/api/connect_host', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ host_id: hostId })
        });

        if (response.error) {
            showAlert('alertContainer', response.error, 'danger');
            return;
        }

        showAlert('alertContainer', 'Connection request sent successfully', 'success');
        setTimeout(() => window.location.href = '/send_file', 2000);
    } catch (error) {
        showAlert('alertContainer', 'Failed to connect to host', 'danger');
    }
}

async function refreshHosts() {
    try {
        const response = await apiRequest('/api/refresh_hosts');
        if (response.error) {
            showAlert('alertContainer', response.error, 'danger');
            return;
        }

        const hostsTable = document.querySelector('#hostsTable tbody');
        if (!hostsTable) return;

        hostsTable.innerHTML = '';
        response.hosts.forEach(host => {
            hostsTable.innerHTML += `
                <tr>
                    <td>${host.name}</td>
                    <td>${host.ip || 'N/A'}</td>
                    <td>${host.port}</td>
                    <td>
                        <span class="badge bg-${host.status_color}">
                            ${host.status}
                        </span>
                    </td>
                    <td>
                        <button class="btn btn-success btn-sm" onclick="connectToHost('${host.id}')">
                            <i class="fas fa-plug me-1"></i>
                            Connect
                        </button>
                    </td>
                </tr>
            `;
        });
    } catch (error) {
        showAlert('alertContainer', 'Failed to refresh hosts list', 'danger');
    }
}

async function respondToHandshake(requestId, action) {
    try {
        const response = await apiRequest('/api/handshake/respond', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                request_id: requestId,
                action: action
            })
        });

        if (response.error) {
            showAlert('alertContainer', response.error, 'danger');
            return;
        }

        showAlert('alertContainer', response.message, 'success');
        setTimeout(() => location.reload(), 2000);
    } catch (error) {
        showAlert('alertContainer', 'Failed to respond to handshake request', 'danger');
    }
}

// File management functions
function validateFileUpload(formElement) {
    const fileInput = formElement.querySelector('input[type="file"]');
    const file = fileInput.files[0];

    if (!file) {
        showAlert('alertContainer', 'Please select a file', 'warning');
        return false;
    }

    const allowedTypes = ['audio/mpeg', 'audio/mp3'];
    if (!allowedTypes.includes(file.type)) {
        showAlert('alertContainer', 'Only MP3 files are allowed', 'warning');
        return false;
    }

    const maxSize = 50 * 1024 * 1024; // 50MB
    if (file.size > maxSize) {
        showAlert('alertContainer', 'File size must be less than 50MB', 'warning');
        return false;
    }

    return true;
}

function initializeFileUpload() {
    const uploadForm = document.getElementById('uploadForm');
    if (uploadForm) {
        uploadForm.onsubmit = (e) => {
            if (!validateFileUpload(uploadForm)) {
                e.preventDefault();
                return false;
            }
            return true;
        };
    }
}

// Theme management
function initializeTheme() {
    const themeToggle = document.createElement('button');
    themeToggle.className = 'theme-toggle';
    themeToggle.innerHTML = '<i class="fas fa-moon"></i>';
    themeToggle.title = 'Chuyển đổi giao diện sáng/tối';
    document.body.appendChild(themeToggle);

    // Initialize theme from localStorage or system preference
    const savedTheme = localStorage.getItem('theme');
    const systemTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    const currentTheme = savedTheme || systemTheme;
    
    document.documentElement.setAttribute('data-bs-theme', currentTheme);
    updateThemeIcon(currentTheme);

    themeToggle.addEventListener('click', () => {
        const currentTheme = document.documentElement.getAttribute('data-bs-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        
        document.documentElement.setAttribute('data-bs-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        updateThemeIcon(newTheme);
    });
}

function updateThemeIcon(theme) {
    const themeToggle = document.querySelector('.theme-toggle');
    if (themeToggle) {
        themeToggle.innerHTML = theme === 'dark' ? 
            '<i class="fas fa-sun"></i>' : 
            '<i class="fas fa-moon"></i>';
    }
}

// Initialize based on current page
document.addEventListener('DOMContentLoaded', function() {
    initializeTheme();
    
    const path = window.location.pathname;
    
    if (path.includes('/choose_host')) {
        refreshHosts();
        // Auto-refresh hosts every 30 seconds
        setInterval(refreshHosts, 30000);
    }
    
    if (path.includes('/send_file')) {
        initializeFileUpload();
    }
    
    // Initialize tooltips and other Bootstrap components
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
});
