// Main JavaScript for SecuritaNova

// Global variables
let uploadArea, fileInput, uploadProgress, uploadContent;
let errorDisplay, errorMessage;
let currentScanId = null;

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeElements();
    setupEventListeners();
});

function initializeElements() {
    uploadArea = document.getElementById('uploadArea');
    fileInput = document.getElementById('fileInput');
    uploadProgress = document.getElementById('uploadProgress');
    uploadContent = document.getElementById('uploadContent');
    errorDisplay = document.getElementById('errorDisplay');
    errorMessage = document.getElementById('errorMessage');
}

function setupEventListeners() {
    if (uploadArea) {
        // Drag and drop events
        uploadArea.addEventListener('dragover', handleDragOver);
        uploadArea.addEventListener('dragleave', handleDragLeave);
        uploadArea.addEventListener('drop', handleDrop);
        uploadArea.addEventListener('click', () => fileInput.click());
    }

    if (fileInput) {
        fileInput.addEventListener('change', handleFileSelect);
    }

    const browseBtn = document.getElementById('browseBtn');
    if (browseBtn) {
        browseBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            fileInput.click();
        });
    }

    // Scan results page event listeners
    setupScanResultsListeners();
}

function setupScanResultsListeners() {
    const downloadReportBtn = document.getElementById('downloadReportBtn');
    const toggleGraphsBtn = document.getElementById('toggleGraphsBtn');
    const toggleDetailsBtn = document.getElementById('toggleDetailsBtn');

    if (downloadReportBtn) {
        downloadReportBtn.addEventListener('click', downloadReport);
    }

    if (toggleGraphsBtn) {
        toggleGraphsBtn.addEventListener('click', toggleGraphs);
    }

    if (toggleDetailsBtn) {
        toggleDetailsBtn.addEventListener('click', toggleDetails);
    }
}

// Drag and drop handlers
function handleDragOver(e) {
    e.preventDefault();
    uploadArea.classList.add('border-purple-400', 'bg-purple-500/20');
}

function handleDragLeave(e) {
    e.preventDefault();
    uploadArea.classList.remove('border-purple-400', 'bg-purple-500/20');
}

function handleDrop(e) {
    e.preventDefault();
    uploadArea.classList.remove('border-purple-400', 'bg-purple-500/20');
    
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        processFile(files[0]);
    }
}

function handleFileSelect(e) {
    const files = e.target.files;
    if (files.length > 0) {
        processFile(files[0]);
    }
}

function processFile(file) {
    // Hide error display
    hideError();

    // Validate file
    if (!validateFile(file)) {
        return;
    }

    // Show upload progress
    showUploadProgress(file);

    // Upload file
    uploadFile(file);
}

function validateFile(file) {
    const maxSize = 500 * 1024 * 1024; // 500MB

    if (file.size > maxSize) {
        showError('File too large. Maximum size is 500MB.');
        return false;
    }

    if (file.size === 0) {
        showError('File is empty. Please select a valid file.');
        return false;
    }

    return true;
}

function showUploadProgress(file) {
    // Hide upload content, show progress
    uploadContent.classList.add('hidden');
    uploadProgress.classList.remove('hidden');

    // Update file info
    const fileInfo = document.getElementById('fileInfo');
    if (fileInfo) {
        fileInfo.innerHTML = `
            <div class="flex justify-between items-center">
                <span><strong>File:</strong> ${file.name}</span>
                <span><strong>Size:</strong> ${formatFileSize(file.size)}</span>
            </div>
        `;
    }
}

function uploadFile(file) {
    const formData = new FormData();
    formData.append('file', file);

    const uploadStatus = document.getElementById('uploadStatus');
    const progressBar = document.getElementById('progressBar');

    // Simulate upload progress
    let progress = 0;
    const progressInterval = setInterval(() => {
        progress += Math.random() * 15;
        if (progress > 90) {
            progress = 90;
        }
        
        progressBar.style.width = `${progress}%`;
        
        if (progress < 30) {
            uploadStatus.textContent = 'Uploading file...';
        } else if (progress < 60) {
            uploadStatus.textContent = 'Validating file...';
        } else if (progress < 90) {
            uploadStatus.textContent = 'Preparing for scan...';
        }
    }, 200);

    fetch('/upload', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        clearInterval(progressInterval);
        
        if (data.error) {
            throw new Error(data.error);
        }

        // Complete progress
        progressBar.style.width = '100%';
        uploadStatus.textContent = 'Upload complete! Redirecting to scan...';

        // Redirect to scan page
        setTimeout(() => {
            window.location.href = `/scan/${data.scan_id}`;
        }, 1000);
    })
    .catch(error => {
        clearInterval(progressInterval);
        console.error('Upload error:', error);
        showError(error.message || 'Upload failed. Please try again.');
        resetUploadArea();
    });
}

function resetUploadArea() {
    uploadContent.classList.remove('hidden');
    uploadProgress.classList.add('hidden');
    
    const progressBar = document.getElementById('progressBar');
    if (progressBar) {
        progressBar.style.width = '0%';
    }
}

function showError(message) {
    if (errorDisplay && errorMessage) {
        errorMessage.textContent = message;
        errorDisplay.classList.remove('hidden');
    }
}

function hideError() {
    if (errorDisplay) {
        errorDisplay.classList.add('hidden');
    }
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Scan monitoring functions
function startScanMonitoring(scanId) {
    currentScanId = scanId;
    
    const progressInterval = setInterval(() => {
        fetch(`/api/scan/${scanId}/progress`)
            .then(response => response.json())
            .then(data => {
                updateScanProgress(data);
                
                if (data.stage === 'complete') {
                    clearInterval(progressInterval);
                    loadScanResults(scanId);
                } else if (data.stage === 'error') {
                    clearInterval(progressInterval);
                    showScanError(data.message);
                }
            })
            .catch(error => {
                console.error('Progress check error:', error);
            });
    }, 1000); // Check every second
}

function updateScanProgress(data) {
    const scanProgressBar = document.getElementById('scanProgressBar');
    const scanPercentage = document.getElementById('scanPercentage');
    const scanStageText = document.getElementById('scanStageText');

    if (scanProgressBar) {
        scanProgressBar.style.width = `${data.progress}%`;
    }

    if (scanPercentage) {
        scanPercentage.textContent = `${data.progress}%`;
    }

    if (scanStageText) {
        scanStageText.textContent = data.message || 'Processing...';
    }
}

function loadScanResults(scanId) {
    // Hide progress, show completion
    const scanSpinner = document.getElementById('scanSpinner');
    const scanComplete = document.getElementById('scanComplete');
    
    if (scanSpinner) scanSpinner.classList.add('hidden');
    if (scanComplete) scanComplete.classList.remove('hidden');

    // Update progress text
    const scanStageText = document.getElementById('scanStageText');
    if (scanStageText) {
        scanStageText.textContent = 'Scan completed successfully';
    }

    // Load results
    fetch(`/api/scan/${scanId}/results`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                throw new Error(data.error);
            }
            
            displayScanResults(data);
            
            // Hide progress section after a delay
            setTimeout(() => {
                const scanProgress = document.getElementById('scanProgress');
                const scanResults = document.getElementById('scanResults');
                
                if (scanProgress) scanProgress.classList.add('hidden');
                if (scanResults) scanResults.classList.remove('hidden');
            }, 2000);
        })
        .catch(error => {
            console.error('Results loading error:', error);
            showScanError(error.message || 'Failed to load scan results');
        });
}

function displayScanResults(data) {
    // Update file metadata
    updateElement('fileName', data.file_name);
    updateElement('fileSize', formatFileSize(data.file_size));
    updateElement('fileType', data.file_type);

    // Update threat level
    const threatLevel = data.overall_threat_level;
    updateElement('threatLevel', threatLevel.level);
    
    const threatLevelElement = document.getElementById('threatLevel');
    const threatIndicator = document.getElementById('threatIndicator');
    
    if (threatLevelElement && threatIndicator) {
        // Set colors based on threat level
        if (threatLevel.color === 'green') {
            threatLevelElement.className = 'text-6xl font-bold mb-2 text-green-400';
            threatIndicator.className = 'w-32 h-32 rounded-full flex items-center justify-center bg-green-500/20 border-2 border-green-500';
            updateElement('threatDescription', 'File appears safe');
        } else if (threatLevel.color === 'yellow') {
            threatLevelElement.className = 'text-6xl font-bold mb-2 text-yellow-400';
            threatIndicator.className = 'w-32 h-32 rounded-full flex items-center justify-center bg-yellow-500/20 border-2 border-yellow-500';
            updateElement('threatDescription', 'Potential security risk detected');
        } else {
            threatLevelElement.className = 'text-6xl font-bold mb-2 text-red-400';
            threatIndicator.className = 'w-32 h-32 rounded-full flex items-center justify-center bg-red-500/20 border-2 border-red-500';
            updateElement('threatDescription', 'Malicious content detected');
        }
    }

    // Store results globally for other functions
    window.scanResultsData = data;

    // Update detailed results sections
    updateDetailedResults(data);
}

function updateDetailedResults(data) {
    // File Validation
    updateModuleStatus('validation', data.validation);
    updateElement('validationDetails', data.validation.message);

    // Hash Analysis
    updateModuleStatus('hash', { status: 'complete' });
    updateElement('hashDetails', `
        <div><strong>MD5:</strong> ${data.hashes.md5}</div>
        <div><strong>SHA256:</strong> ${data.hashes.sha256}</div>
    `);

    // Database Lookup
    updateModuleStatus('database', data.database_lookup);
    updateElement('databaseDetails', data.database_lookup.message);

    // Sandbox Analysis
    updateModuleStatus('sandbox', { status: data.sandbox_analysis.risk_level });
    updateElement('sandboxDetails', `
        <div><strong>Risk Level:</strong> ${data.sandbox_analysis.risk_level}</div>
        <div><strong>Findings:</strong></div>
        <ul class="list-disc list-inside mt-2">
            ${data.sandbox_analysis.findings.map(finding => `<li>${finding}</li>`).join('')}
        </ul>
    `);

    // Heuristic Analysis
    updateModuleStatus('heuristic', { status: `${data.heuristic_analysis.risk_score}/100` });
    updateElement('heuristicDetails', `
        <div><strong>Risk Score:</strong> ${data.heuristic_analysis.risk_score}/100</div>
        <div><strong>Findings:</strong></div>
        <ul class="list-disc list-inside mt-2">
            ${data.heuristic_analysis.findings.map(finding => `<li>${finding}</li>`).join('')}
        </ul>
    `);

    // Code Analysis
    updateModuleStatus('code', { status: `${data.code_analysis.risk_score || 0}/100` });
    updateElement('codeDetails', `
        <div><strong>Risk Score:</strong> ${data.code_analysis.risk_score || 0}/100</div>
        <div><strong>Findings:</strong></div>
        <ul class="list-disc list-inside mt-2">
            ${(data.code_analysis.findings || []).map(finding => `<li>${finding}</li>`).join('')}
        </ul>
    `);

    // Gemini AI Analysis
    updateModuleStatus('gemini', data.gemini_analysis);
    updateElement('geminiDetails', `
        <div><strong>Classification:</strong> ${data.gemini_analysis.classification}</div>
        <div><strong>Confidence:</strong> ${(data.gemini_analysis.confidence * 100).toFixed(1)}%</div>
        <div><strong>Explanation:</strong> ${data.gemini_analysis.explanation}</div>
        <div><strong>Recommendation:</strong> ${data.gemini_analysis.recommendation}</div>
    `);
}

function updateModuleStatus(module, data) {
    const statusElement = document.getElementById(`${module}Status`);
    if (!statusElement) return;

    let statusClass = 'bg-green-500/20 text-green-300 border border-green-500/50';
    let statusText = 'Complete';

    if (data.status === 'error' || data.status === 'failed') {
        statusClass = 'bg-red-500/20 text-red-300 border border-red-500/50';
        statusText = 'Error';
    } else if (data.status === 'malicious') {
        statusClass = 'bg-red-500/20 text-red-300 border border-red-500/50';
        statusText = 'Malicious';
    } else if (data.status === 'suspicious' || data.status === 'warning') {
        statusClass = 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/50';
        statusText = 'Warning';
    } else if (typeof data.status === 'string' && data.status.includes('/')) {
        statusText = data.status; // For score displays
    }

    statusElement.className = `px-3 py-1 rounded-full text-sm font-medium ${statusClass}`;
    statusElement.textContent = statusText;
}

function updateElement(id, content) {
    const element = document.getElementById(id);
    if (element) {
        if (typeof content === 'string' && content.includes('<')) {
            element.innerHTML = content;
        } else {
            element.textContent = content;
        }
    }
}

function showScanError(message) {
    const scanStageText = document.getElementById('scanStageText');
    if (scanStageText) {
        scanStageText.textContent = `Error: ${message}`;
        scanStageText.className = 'text-red-400 mb-4';
    }
}

// Button handlers for scan results page
function downloadReport() {
    if (currentScanId) {
        window.open(`/api/scan/${currentScanId}/report`, '_blank');
    }
}

function toggleGraphs() {
    const graphs = document.getElementById('analysisGraphs');
    const button = document.getElementById('toggleGraphsBtn');
    
    if (graphs && button) {
        if (graphs.classList.contains('hidden')) {
            graphs.classList.remove('hidden');
            button.innerHTML = '<i data-feather="eye-off" class="w-5 h-5 inline mr-2"></i>Hide Graphs';
            
            // Initialize graphs if data is available
            if (window.scanResultsData) {
                setTimeout(() => {
                    initializeGraphs(window.scanResultsData);
                    feather.replace();
                }, 100);
            }
        } else {
            graphs.classList.add('hidden');
            button.innerHTML = '<i data-feather="bar-chart-2" class="w-5 h-5 inline mr-2"></i>View Analysis Graphs';
        }
        feather.replace();
    }
}

function toggleDetails() {
    const details = document.getElementById('detailedResults');
    const button = document.getElementById('toggleDetailsBtn');
    
    if (details && button) {
        if (details.classList.contains('hidden')) {
            details.classList.remove('hidden');
            button.innerHTML = '<i data-feather="eye-off" class="w-5 h-5 inline mr-2"></i>Hide Details';
        } else {
            details.classList.add('hidden');
            button.innerHTML = '<i data-feather="list" class="w-5 h-5 inline mr-2"></i>Detailed Results';
        }
        feather.replace();
    }
}
