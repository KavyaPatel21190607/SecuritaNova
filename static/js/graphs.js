// Graphs.js - Canvas-based graphing for SecuritaNova

function initializeGraphs(scanData) {
    if (!scanData) return;
    
    try {
        drawRiskBarChart(scanData);
        drawProgressLineChart(scanData);
    } catch (error) {
        console.error('Graph initialization error:', error);
    }
}

function drawRiskBarChart(scanData) {
    const canvas = document.getElementById('riskBarChart');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    const rect = canvas.getBoundingClientRect();
    
    // Set canvas size
    canvas.width = rect.width * window.devicePixelRatio;
    canvas.height = rect.height * window.devicePixelRatio;
    ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
    
    const width = rect.width;
    const height = rect.height;
    
    // Clear canvas
    ctx.clearRect(0, 0, width, height);
    
    // Chart margins and dimensions
    const margin = { top: 20, right: 20, bottom: 60, left: 60 };
    const chartWidth = width - margin.left - margin.right;
    const chartHeight = height - margin.top - margin.bottom;
    
    // Prepare data
    const modules = [
        { name: 'Database', score: getScoreFromLookup(scanData.database_lookup) },
        { name: 'Sandbox', score: getScoreFromSandbox(scanData.sandbox_analysis) },
        { name: 'Heuristic', score: scanData.heuristic_analysis.risk_score },
        { name: 'Code', score: scanData.code_analysis.risk_score || 0 },
        { name: 'Gemini AI', score: getScoreFromGemini(scanData.gemini_analysis) }
    ];
    
    const maxScore = 100;
    const barWidth = (chartWidth / modules.length) * 0.7;
    const barSpacing = (chartWidth / modules.length) * 0.3;
    
    // Draw background
    ctx.fillStyle = 'rgba(255, 255, 255, 0.05)';
    ctx.fillRect(margin.left, margin.top, chartWidth, chartHeight);
    
    // Draw grid lines
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.1)';
    ctx.lineWidth = 1;
    
    for (let i = 0; i <= 5; i++) {
        const y = margin.top + (chartHeight / 5) * i;
        ctx.beginPath();
        ctx.moveTo(margin.left, y);
        ctx.lineTo(margin.left + chartWidth, y);
        ctx.stroke();
    }
    
    // Draw Y-axis labels
    ctx.fillStyle = 'rgba(255, 255, 255, 0.7)';
    ctx.font = '12px Arial';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    
    for (let i = 0; i <= 5; i++) {
        const value = (5 - i) * 20;
        const y = margin.top + (chartHeight / 5) * i;
        ctx.fillText(value.toString(), margin.left - 10, y);
    }
    
    // Draw bars
    modules.forEach((module, index) => {
        const barHeight = Math.max((module.score / maxScore) * chartHeight, 2); // Minimum height of 2px
        const x = margin.left + (index * (barWidth + barSpacing)) + (barSpacing / 2);
        const y = margin.top + chartHeight - barHeight;
        
        // Determine bar color based on score
        let barColor;
        if (module.score < 30) {
            barColor = 'rgba(34, 197, 94, 0.8)'; // Green
        } else if (module.score < 70) {
            barColor = 'rgba(234, 179, 8, 0.8)'; // Yellow
        } else {
            barColor = 'rgba(239, 68, 68, 0.8)'; // Red
        }
        
        // Draw bar
        ctx.fillStyle = barColor;
        ctx.fillRect(x, y, barWidth, barHeight);
        
        // Draw bar border
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.3)';
        ctx.lineWidth = 1;
        ctx.strokeRect(x, y, barWidth, barHeight);
        
        // Draw score text on bar or above it
        ctx.fillStyle = 'white';
        ctx.font = 'bold 12px Arial';
        ctx.textAlign = 'center';
        
        if (barHeight > 25) {
            // Text inside bar
            ctx.textBaseline = 'middle';
            ctx.fillText(module.score.toFixed(0), x + barWidth / 2, y + barHeight / 2);
        } else {
            // Text above bar
            ctx.textBaseline = 'bottom';
            ctx.fillText(module.score.toFixed(0), x + barWidth / 2, y - 5);
        }
        
        // Draw module name
        ctx.fillStyle = 'rgba(255, 255, 255, 0.9)';
        ctx.font = '11px Arial';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        
        // Handle long names by wrapping or abbreviating
        let displayName = module.name;
        if (module.name === 'Gemini AI') {
            displayName = 'AI';
        }
        ctx.fillText(displayName, x + barWidth / 2, margin.top + chartHeight + 10);
    });
    
    // Draw axes
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.5)';
    ctx.lineWidth = 2;
    
    // Y-axis
    ctx.beginPath();
    ctx.moveTo(margin.left, margin.top);
    ctx.lineTo(margin.left, margin.top + chartHeight);
    ctx.stroke();
    
    // X-axis
    ctx.beginPath();
    ctx.moveTo(margin.left, margin.top + chartHeight);
    ctx.lineTo(margin.left + chartWidth, margin.top + chartHeight);
    ctx.stroke();
    
    // Draw Y-axis label
    ctx.save();
    ctx.translate(20, margin.top + chartHeight / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.fillStyle = 'rgba(255, 255, 255, 0.9)';
    ctx.font = 'bold 14px Arial';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('Risk Score', 0, 0);
    ctx.restore();
    
    // Draw title
    ctx.fillStyle = 'rgba(255, 255, 255, 0.9)';
    ctx.font = 'bold 16px Arial';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    ctx.fillText('Risk Assessment by Module', width / 2, 5);
}

function drawProgressLineChart(scanData) {
    const canvas = document.getElementById('progressLineChart');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    const rect = canvas.getBoundingClientRect();
    
    // Set canvas size
    canvas.width = rect.width * window.devicePixelRatio;
    canvas.height = rect.height * window.devicePixelRatio;
    ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
    
    const width = rect.width;
    const height = rect.height;
    
    // Clear canvas
    ctx.clearRect(0, 0, width, height);
    
    // Chart margins and dimensions
    const margin = { top: 20, right: 20, bottom: 60, left: 60 };
    const chartWidth = width - margin.left - margin.right;
    const chartHeight = height - margin.top - margin.bottom;
    
    // Prepare progression data - show cumulative maximum risk found at each stage
    let cumulativeRisk = 0;
    const progressionData = [
        { stage: 'Start', risk: 0 },
        { stage: 'Database', risk: (cumulativeRisk = Math.max(cumulativeRisk, getScoreFromLookup(scanData.database_lookup))) },
        { stage: 'Sandbox', risk: (cumulativeRisk = Math.max(cumulativeRisk, getScoreFromSandbox(scanData.sandbox_analysis))) },
        { stage: 'Heuristic', risk: (cumulativeRisk = Math.max(cumulativeRisk, scanData.heuristic_analysis.risk_score)) },
        { stage: 'Code', risk: (cumulativeRisk = Math.max(cumulativeRisk, scanData.code_analysis.risk_score || 0)) },
        { stage: 'AI Final', risk: scanData.overall_threat_level.score }
    ];
    
    const maxRisk = 100;
    
    // Draw background
    ctx.fillStyle = 'rgba(255, 255, 255, 0.05)';
    ctx.fillRect(margin.left, margin.top, chartWidth, chartHeight);
    
    // Draw grid lines
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.1)';
    ctx.lineWidth = 1;
    
    // Horizontal grid lines
    for (let i = 0; i <= 5; i++) {
        const y = margin.top + (chartHeight / 5) * i;
        ctx.beginPath();
        ctx.moveTo(margin.left, y);
        ctx.lineTo(margin.left + chartWidth, y);
        ctx.stroke();
    }
    
    // Vertical grid lines
    for (let i = 0; i < progressionData.length; i++) {
        const x = margin.left + (chartWidth / (progressionData.length - 1)) * i;
        ctx.beginPath();
        ctx.moveTo(x, margin.top);
        ctx.lineTo(x, margin.top + chartHeight);
        ctx.stroke();
    }
    
    // Draw Y-axis labels
    ctx.fillStyle = 'rgba(255, 255, 255, 0.7)';
    ctx.font = '12px Arial';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    
    for (let i = 0; i <= 5; i++) {
        const value = (5 - i) * 20;
        const y = margin.top + (chartHeight / 5) * i;
        ctx.fillText(value.toString(), margin.left - 10, y);
    }
    
    // Draw line
    ctx.strokeStyle = 'rgba(147, 51, 234, 1)'; // Purple
    ctx.lineWidth = 3;
    ctx.beginPath();
    
    progressionData.forEach((point, index) => {
        const x = margin.left + (chartWidth / (progressionData.length - 1)) * index;
        const y = margin.top + chartHeight - (point.risk / maxRisk) * chartHeight;
        
        if (index === 0) {
            ctx.moveTo(x, y);
        } else {
            ctx.lineTo(x, y);
        }
    });
    
    ctx.stroke();
    
    // Draw data points
    progressionData.forEach((point, index) => {
        const x = margin.left + (chartWidth / (progressionData.length - 1)) * index;
        const y = margin.top + chartHeight - (point.risk / maxRisk) * chartHeight;
        
        // Point circle
        ctx.fillStyle = 'rgba(147, 51, 234, 1)';
        ctx.beginPath();
        ctx.arc(x, y, 6, 0, 2 * Math.PI);
        ctx.fill();
        
        // Point border
        ctx.strokeStyle = 'white';
        ctx.lineWidth = 2;
        ctx.stroke();
        
        // Value label - only show if risk > 0 to avoid clutter
        if (point.risk > 0) {
            ctx.fillStyle = 'rgba(255, 255, 255, 0.9)';
            ctx.font = 'bold 11px Arial';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'bottom';
            ctx.fillText(point.risk.toFixed(0), x, y - 10);
        }
    });
    
    // Draw X-axis labels
    ctx.fillStyle = 'rgba(255, 255, 255, 0.9)';
    ctx.font = '10px Arial';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    
    progressionData.forEach((point, index) => {
        const x = margin.left + (chartWidth / (progressionData.length - 1)) * index;
        let displayStage = point.stage;
        if (point.stage === 'AI Final') {
            displayStage = 'AI';
        }
        ctx.fillText(displayStage, x, margin.top + chartHeight + 10);
    });
    
    // Draw axes
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.5)';
    ctx.lineWidth = 2;
    
    // Y-axis
    ctx.beginPath();
    ctx.moveTo(margin.left, margin.top);
    ctx.lineTo(margin.left, margin.top + chartHeight);
    ctx.stroke();
    
    // X-axis
    ctx.beginPath();
    ctx.moveTo(margin.left, margin.top + chartHeight);
    ctx.lineTo(margin.left + chartWidth, margin.top + chartHeight);
    ctx.stroke();
    
    // Draw Y-axis label
    ctx.save();
    ctx.translate(20, margin.top + chartHeight / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.fillStyle = 'rgba(255, 255, 255, 0.9)';
    ctx.font = 'bold 14px Arial';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('Risk Level', 0, 0);
    ctx.restore();
    
    // Draw title
    ctx.fillStyle = 'rgba(255, 255, 255, 0.9)';
    ctx.font = 'bold 16px Arial';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    ctx.fillText('Risk Progression Throughout Scan', width / 2, 5);
}

// Helper functions to convert scan results to numeric scores
function getScoreFromLookup(lookupResult) {
    switch (lookupResult.status) {
        case 'malicious': return 100;
        case 'suspicious': return 70;
        case 'clean': return 10;
        default: return 0;
    }
}

function getScoreFromSandbox(sandboxResult) {
    switch (sandboxResult.risk_level) {
        case 'High': return 80;
        case 'Medium': return 50;
        case 'Low': return 20;
        default: return 0;
    }
}

function getScoreFromGemini(geminiResult) {
    const baseScore = {
        'Malicious': 90,
        'Suspicious': 60,
        'Safe': 10
    }[geminiResult.classification] || 10;
    
    // Adjust by confidence
    return baseScore * (geminiResult.confidence || 0.5);
}

// Handle window resize
window.addEventListener('resize', function() {
    if (window.scanResultsData) {
        setTimeout(() => {
            initializeGraphs(window.scanResultsData);
        }, 100);
    }
});
