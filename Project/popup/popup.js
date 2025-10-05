document.addEventListener('DOMContentLoaded', function() {
    const urlInput = document.getElementById('url-input');
    const startAuditBtn = document.getElementById('start-audit-btn');
    const reportDashboard = document.getElementById('report-dashboard');
    const exportPdfBtn = document.getElementById('export-pdf-btn');
    const exportJsonBtn = document.getElementById('export-json-btn');
    const viewHistoryBtn = document.getElementById('view-history-btn');
    const historyList = document.getElementById('history-list');
    const progressContainer = document.getElementById('progress-container');
    const progressBarInner = document.querySelector('.progress-bar-inner');
    const progressText = document.getElementById('progress-text');
    const footerActions = document.querySelector('.footer-actions');

    let currentReport = null;
    let progressInterval = null;

    browser.tabs.query({ active: true, currentWindow: true }).then((tabs) => {
        if (tabs[0] && tabs[0].url && tabs[0].url !== 'about:newtab') {
            urlInput.value = tabs[0].url;
        }
    });

    startAuditBtn.addEventListener('click', () => {
        const url = urlInput.value;
        if (url) {
            startProgress();
            browser.runtime.sendMessage({ action: 'startAudit', url: url });
        } else {
            urlInput.focus();
        }
    });

    browser.runtime.onMessage.addListener((message) => {
        if (message.action === 'displayReport') {
            currentReport = message.report;
            completeProgress();
            displayReport(currentReport);
            footerActions.classList.remove('hidden');
        }
    });

    function startProgress() {
        reportDashboard.innerHTML = '';
        historyList.classList.add('hidden');
        footerActions.classList.add('hidden');
        progressContainer.classList.remove('hidden');
        let width = 0;
        progressBarInner.style.width = '0%';
        progressText.textContent = 'Initializing...';
        
        progressInterval = setInterval(() => {
            width += 5;
            if (width > 95) width = 95; // Don't complete until report is back
            progressBarInner.style.width = width + '%';
            if (width < 30) progressText.textContent = 'Analyzing DOM...';
            else if (width < 60) progressText.textContent = 'Checking performance...';
            else if (width < 85) progressText.textContent = 'Auditing security...';
            else progressText.textContent = 'Finalizing report...';
        }, 200);
    }

    function completeProgress() {
        clearInterval(progressInterval);
        progressBarInner.style.width = '100%';
        progressText.textContent = 'Audit Complete!';
        setTimeout(() => progressContainer.classList.add('hidden'), 1000);
    }

    function displayReport(report) {
        reportDashboard.innerHTML = '';
        const categoryColors = {
            Security: '#e74c3c',
            Performance: '#2ecc71',
            SEO: '#3498db',
            Accessibility: '#f39c12'
        };

        for (const category in report) {
            const card = document.createElement('div');
            card.className = 'report-card';
            card.style.borderLeftColor = categoryColors[category] || '#ccc';

            const title = document.createElement('h2');
            title.innerHTML = `${category} <span class="score">${report[category].score}/100</span>`;
            card.appendChild(title);

            report[category].issues.forEach(issue => {
                const issueDetails = document.createElement('div');
                issueDetails.className = 'report-item';

                if (typeof issue === 'string') {
                    issueDetails.textContent = issue;
                } else {
                    const issueTitle = document.createElement('div');
                    issueTitle.className = 'issue-title';
                    issueTitle.textContent = issue.title;

                    const issueDescription = document.createElement('p');
                    issueDescription.className = 'issue-description';
                    issueDescription.textContent = issue.description;
                    
                    const issueRemediation = document.createElement('p');
                    issueRemediation.className = 'issue-remediation';
                    issueRemediation.innerHTML = `<strong>Recommendation:</strong> ${issue.remediation}`;

                    issueDetails.appendChild(issueTitle);
                    issueDetails.appendChild(issueDescription);
                    issueDetails.appendChild(issueRemediation);
                }
                card.appendChild(issueDetails);
            });
            reportDashboard.appendChild(card);
        }
    }

    exportJsonBtn.addEventListener('click', () => {
        if (currentReport) exportAsJSON(currentReport);
    });

    exportPdfBtn.addEventListener('click', () => {
        if (currentReport) exportAsPDF(currentReport);
    });

    function exportAsJSON(report) {
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report, null, 2));
        const downloadAnchorNode = document.createElement('a');
        downloadAnchorNode.setAttribute("href", dataStr);
        downloadAnchorNode.setAttribute("download", "audit-report.json");
        document.body.appendChild(downloadAnchorNode);
        downloadAnchorNode.click();
        downloadAnchorNode.remove();
    }

    function exportAsPDF(report) {
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        let y = 15;
        doc.setFontSize(18);
        doc.text('Website Audit Report', 10, y); y += 10;

        for (const category in report) {
            doc.setFontSize(14);
            doc.text(`${category} (Score: ${report[category].score}/100)`, 10, y); y += 7;
            doc.setFontSize(10);
            report[category].issues.forEach(issue => {
                if (typeof issue === 'string') {
                    const lines = doc.splitTextToSize(issue, 180);
                    doc.text(lines, 15, y); 
                    y += lines.length * 5;
                } else {
                    doc.setFont(undefined, 'bold');
                    doc.text(issue.title, 15, y); y += 6;
                    doc.setFont(undefined, 'normal');
                    let lines = doc.splitTextToSize(`Description: ${issue.description}`, 180);
                    doc.text(lines, 15, y); y += lines.length * 5;
                    lines = doc.splitTextToSize(`Remediation: ${issue.remediation}`, 180);
                    doc.text(lines, 15, y); y += lines.length * 5;
                }
                y += 3;
                if (y > 280) { doc.addPage(); y = 15; }
            });
            y += 5;
        }
        doc.save('audit-report.pdf');
    }

    viewHistoryBtn.addEventListener('click', () => {
        const isHidden = historyList.classList.contains('hidden');
        if (isHidden) {
            browser.runtime.sendMessage({ action: 'getHistory' }, (response) => {
                if (response && response.history) {
                    renderHistory(response.history);
                    historyList.classList.remove('hidden');
                }
            });
        } else {
            historyList.classList.add('hidden');
        }
    });

    function renderHistory(history) {
        historyList.innerHTML = '';
        const sortedHistory = Object.entries(history).sort((a, b) => new Date(b[1].date) - new Date(a[1].date));

        if (sortedHistory.length === 0) {
            historyList.innerHTML = '<p class="history-item">No past audits found.</p>';
            return;
        }

        for (const [id, item] of sortedHistory) {
            const historyItem = document.createElement('div');
            historyItem.className = 'history-item';
            historyItem.innerHTML = `<strong>${new URL(item.url).hostname}</strong><br><small>${new Date(item.date).toLocaleString()}</small>`;
            historyItem.addEventListener('click', () => {
                currentReport = item.report;
                displayReport(item.report);
                historyList.classList.add('hidden');
                footerActions.classList.remove('hidden');
            });
            historyList.appendChild(historyItem);
        }
    }
});
