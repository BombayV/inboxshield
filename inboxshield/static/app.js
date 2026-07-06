document.addEventListener('DOMContentLoaded', () => {
    fetchMetrics();
    fetchEmails();

    document.getElementById('refresh-btn').addEventListener('click', () => {
        fetchMetrics();
        fetchEmails();
    });

    document.getElementById('close-modal').addEventListener('click', closeModal);
    document.getElementById('detail-modal').addEventListener('click', (e) => {
        if (e.target.id === 'detail-modal') {
            closeModal();
        }
    });
});

async function fetchMetrics() {
    try {
        const res = await fetch('api/metrics');
        const data = await res.json();
        
        animateValue('metric-total', data.total);
        animateValue('metric-safe', data.safe);
        animateValue('metric-suspicious', data.suspicious);
        animateValue('metric-phishing', data.phishing);
    } catch (err) {
        console.error("Failed to fetch metrics", err);
    }
}

async function fetchEmails() {
    try {
        const res = await fetch('api/emails');
        const data = await res.json();
        const tbody = document.getElementById('emails-tbody');
        tbody.innerHTML = '';

        if (data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted)">No emails analyzed yet.</td></tr>';
            return;
        }

        data.forEach(email => {
            const tr = document.createElement('tr');
            const verdictLower = (email.verdict || 'unknown').toLowerCase();
            const date = new Date(email.processed_at).toLocaleString();
            
            tr.innerHTML = `
                <td>${date}</td>
                <td>${escapeHtml(email.sender)}</td>
                <td>${escapeHtml(email.subject || 'No Subject')}</td>
                <td><strong>${email.threat_score}</strong>/100</td>
                <td><span class="badge ${verdictLower}">${email.verdict}</span></td>
            `;
            
            tr.addEventListener('click', () => openEmailDetails(email.id));
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error("Failed to fetch emails", err);
    }
}

async function openEmailDetails(emailId) {
    try {
        const res = await fetch(`api/emails/${emailId}`);
        const data = await res.json();
        
        if (data.error) {
            alert(data.error);
            return;
        }

        const email = data.email;
        document.getElementById('modal-subject').textContent = email.subject || 'No Subject';
        
        const verdictLower = (email.verdict || 'unknown').toLowerCase();
        const badge = document.getElementById('modal-verdict-badge');
        badge.className = `badge ${verdictLower}`;
        badge.textContent = email.verdict;

        document.getElementById('modal-sender').textContent = email.sender;
        document.getElementById('modal-date').textContent = new Date(email.processed_at).toLocaleString();
        document.getElementById('modal-score').textContent = email.threat_score;
        document.getElementById('modal-summary').textContent = email.analysis_summary || "No summary provided.";

        // URLs
        const urlTbody = document.getElementById('modal-urls-tbody');
        urlTbody.innerHTML = '';
        if (data.urls.length === 0) {
            urlTbody.innerHTML = '<tr><td colspan="3">No URLs extracted.</td></tr>';
        } else {
            data.urls.forEach(u => {
                const tr = document.createElement('tr');
                const uVerdictLower = (u.verdict || 'unknown').toLowerCase();
                tr.innerHTML = `
                    <td style="word-break: break-all;">${escapeHtml(u.domain || u.original_url)}</td>
                    <td>${u.vt_malicious_count || 0} hits</td>
                    <td><span class="badge ${uVerdictLower}">${u.verdict}</span></td>
                `;
                urlTbody.appendChild(tr);
            });
        }

        // Logs
        const logsContainer = document.getElementById('modal-logs-container');
        logsContainer.innerHTML = '';
        if (data.logs.length === 0) {
            logsContainer.innerHTML = '<div class="log-box">No logs available.</div>';
        } else {
            const logBox = document.createElement('div');
            logBox.className = 'log-box';
            data.logs.forEach(log => {
                const d = new Date(log.timestamp).toLocaleTimeString();
                logBox.innerHTML += `
                    <div class="log-entry">
                        <span class="log-agent">[${log.agent_name}]</span>
                        <span class="log-time">${d}</span>
                        <div style="margin-top: 0.25rem;">${escapeHtml(log.log_message)}</div>
                    </div>
                `;
            });
            logsContainer.appendChild(logBox);
        }

        document.getElementById('detail-modal').classList.add('active');
    } catch (err) {
        console.error("Failed to load details", err);
    }
}

function closeModal() {
    document.getElementById('detail-modal').classList.remove('active');
}

// Utils
function escapeHtml(unsafe) {
    if (!unsafe) return '';
    return unsafe
         .toString()
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

function animateValue(id, end, duration = 1000) {
    const obj = document.getElementById(id);
    if (!obj) return;
    const start = 0;
    let startTimestamp = null;
    const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        obj.innerHTML = Math.floor(progress * (end - start) + start);
        if (progress < 1) {
            window.requestAnimationFrame(step);
        }
    };
    window.requestAnimationFrame(step);
}
