browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    console.log('Background received message:', message);
    if (message.action === 'startAudit') {
        console.log('Starting audit for URL:', message.url);
        runAudit(message.url);
    } else if (message.action === 'getHistory') {
        getAuditHistory().then(history => sendResponse({ history }));
        return true; // Required for async sendResponse
    }
});

async function runAudit(url) {
    console.log(`[background] Starting audit for ${url}`);
    try {
        const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
        if (!tab) {
            console.error('[background] No active tab found.');
            return;
        }

        console.log(`[background] Auditing tab ${tab.id} with URL: ${tab.url}`);

        // Helper to send messages with a timeout
        const sendMessageWithTimeout = (tabId, message, timeout = 5000) => {
            return new Promise((resolve, reject) => {
                const timer = setTimeout(() => {
                    reject(new Error(`Message timed out: ${message.action}`));
                }, timeout);

                browser.tabs.sendMessage(tabId, message)
                    .then(response => {
                        clearTimeout(timer);
                        resolve(response);
                    })
                    .catch(error => {
                        clearTimeout(timer);
                        reject(error);
                    });
            });
        };

        let domInfo = { forms: [] };
        let performanceInfo = { loadTime: 0, resources: [] };
        let seoInfo = { seoInfo: {} };
        let accessibilityInfo = { accessibilityInfo: {} };
        let advancedSecurityInfo = { mixedContent: [], insecureLinks: [] };

        try { domInfo = await sendMessageWithTimeout(tab.id, { action: 'getDOMInfo' }); } catch (e) { console.error('[background] Failed to get DOM info:', e); }
        try { performanceInfo = await sendMessageWithTimeout(tab.id, { action: 'getPerformanceInfo' }); } catch (e) { console.error('[background] Failed to get Performance info:', e); }
        try { seoInfo = await sendMessageWithTimeout(tab.id, { action: 'getSeoInfo' }); } catch (e) { console.error('[background] Failed to get SEO info:', e); }
        try { accessibilityInfo = await sendMessageWithTimeout(tab.id, { action: 'getAccessibilityInfo' }); } catch (e) { console.error('[background] Failed to get Accessibility info:', e); }
        try { advancedSecurityInfo = await sendMessageWithTimeout(tab.id, { action: 'getAdvancedSecurityInfo' }); } catch (e) { console.error('[background] Failed to get Advanced Security info:', e); }

        console.log('[background] All data received from content script.');

        const securityReport = await checkSecurity(url, domInfo, advancedSecurityInfo);
        const performanceReport = await checkPerformance(performanceInfo);
        const seoReport = await checkSeo(url, seoInfo);
        const accessibilityReport = await checkAccessibility(accessibilityInfo);

        const fullReport = {
            'Security': securityReport,
            'Performance': performanceReport,
            'SEO': seoReport,
            'Accessibility': accessibilityReport,
        };

        await saveAuditReport(url, fullReport);

        browser.runtime.sendMessage({ action: 'displayReport', report: fullReport });

    } catch (error) {
        console.error('[background] A critical error occurred during the audit:', error);
        browser.runtime.sendMessage({
            action: 'displayReport',
            report: {
                'Error': {
                    score: 0,
                    issues: [`An unexpected error occurred: ${error.message}`]
                }
            }
        });
    }
}

async function checkSecurity(url, domInfo, advancedSecurityInfo) {
    const issues = [];
    let score = 100;
    const urlObj = new URL(url);

    // 1. Check for HTTPS
    if (urlObj.protocol !== 'https:') {
        issues.push({
            title: 'HTTPS Not Used',
            description: 'The site is not served over HTTPS, which means data transmitted between the user and the server is not encrypted.',
            remediation: 'Enable HTTPS on your server. Use a free certificate from a service like Let\'s Encrypt if needed.'
        });
        score -= 20;
    }

    // 2. Fetch headers and check them
    try {
        const response = await fetch(url, { method: 'HEAD' }); // Use HEAD to be faster
        const headers = response.headers;

        // Check Content-Security-Policy for weaknesses
        const csp = headers.get('content-security-policy');
        if (!csp) {
            issues.push({ title: 'Missing Header: Content-Security-Policy', description: 'CSP is a critical defense against XSS attacks.', remediation: 'Implement a strong Content-Security-Policy that specifies trusted sources for content.' });
            score -= 10;
        } else {
            if (csp.includes("'unsafe-inline'")) {
                issues.push({ title: 'Weak CSP: Unsafe Inline Scripts', description: 'The CSP allows inline scripts, which increases XSS risk.', remediation: 'Avoid `unsafe-inline`. Use nonce- or hash-based CSP for scripts.' });
                score -= 5;
            }
            if (csp.includes("'unsafe-eval'")) {
                issues.push({ title: 'Weak CSP: Unsafe Eval', description: 'The CSP allows `eval()`, which can execute arbitrary code.', remediation: 'Avoid `unsafe-eval` as it is a significant security risk.' });
                score -= 5;
            }
        }

        // Check other critical headers
        if (!headers.has('x-content-type-options')) {
            issues.push({ title: 'Missing Header: X-Content-Type-Options', description: 'This header prevents MIME-sniffing attacks.', remediation: 'Set `X-Content-Type-Options: nosniff`.' });
            score -= 5;
        }

        if (!headers.has('x-frame-options')) {
            issues.push({ title: 'Missing Header: X-Frame-Options', description: 'This header protects against clickjacking attacks.', remediation: 'Set `X-Frame-Options: DENY` or `SAMEORIGIN`.' });
            score -= 5;
        }

        if (urlObj.protocol === 'https:' && !headers.has('strict-transport-security')) {
            issues.push({ title: 'Missing Header: Strict-Transport-Security', description: 'HSTS ensures browsers only connect via HTTPS.', remediation: 'Add a Strict-Transport-Security header, e.g., `max-age=31536000; includeSubDomains`.' });
            score -= 5;
        }

        // Check for information-leaking headers
        if (headers.has('server') || headers.has('x-powered-by')) {
            issues.push({
                title: 'Information Leakage in Headers',
                description: `The 'Server' or 'X-Powered-By' header reveals specific technology information, which could help an attacker. Found: ${headers.get('server') || headers.get('x-powered-by')}`,
                remediation: 'Configure your web server to suppress or change these headers to be less descriptive.'
            });
            score -= 2;
        }

    } catch (error) {
        issues.push({
            title: 'Could Not Fetch Headers',
            description: `The tool was unable to fetch and analyze the HTTP headers. This may be due to network issues or security policies. ${error.message}`,
            remediation: 'Ensure the page is accessible and that there are no network policies blocking HEAD requests.'
        });
        score -= 10;
    }

    // 3. Check for insecure cookies
    try {
        const cookies = await browser.cookies.getAll({ domain: urlObj.hostname });
        cookies.forEach(cookie => {
            if (!cookie.httpOnly) {
                issues.push({
                    title: 'Cookie Missing HttpOnly Flag',
                    description: `The cookie '${cookie.name}' does not have the HttpOnly flag, making it accessible to client-side scripts and vulnerable to XSS attacks.`,
                    remediation: `Set the HttpOnly flag for the '${cookie.name}' cookie to prevent it from being accessed via JavaScript.`
                });
                score -= 3;
            }
            if (urlObj.protocol === 'https:' && !cookie.secure) {
                issues.push({
                    title: 'Cookie Missing Secure Flag',
                    description: `The cookie '${cookie.name}' is served over HTTPS but is missing the Secure flag, meaning it could be sent over an insecure connection.`,
                    remediation: `Set the Secure flag for the '${cookie.name}' cookie to ensure it is only sent over HTTPS.`
                });
                score -= 3;
            }
            if (!cookie.sameSite || cookie.sameSite === 'no_restriction') {
                issues.push({
                    title: 'Cookie with Weak SameSite Policy',
                    description: `The cookie '${cookie.name}' has a weak SameSite policy ('None' without Secure, or not set), which could make it vulnerable to CSRF attacks.`,
                    remediation: `Set the SameSite attribute for the '${cookie.name}' cookie to 'Lax' or 'Strict' to control when it is sent with cross-site requests.`
                });
                score -= 2;
            }
        });
    } catch (e) {
        issues.push({
            title: 'Could Not Check Cookies',
            description: 'The tool was unable to check cookies. This is likely because the "cookies" permission has not been granted in the extension manifest or was denied by the user.',
            remediation: 'Ensure the extension has the necessary "cookies" permission in its manifest.json file.'
        });
    }

    // 4. Check for mixed content
    if (advancedSecurityInfo.mixedContent && advancedSecurityInfo.mixedContent.length > 0) {
        issues.push({
            title: 'Mixed Content Found',
            description: `The page loads ${advancedSecurityInfo.mixedContent.length} insecure resources (e.g., images, scripts) over HTTP on an HTTPS page.`,
            remediation: 'Ensure all assets (images, scripts, stylesheets, etc.) are loaded over HTTPS.'
        });
        score -= advancedSecurityInfo.mixedContent.length * 4;
    }

    // 5. Check for insecure external links
    if (advancedSecurityInfo.insecureLinks && advancedSecurityInfo.insecureLinks.length > 0) {
        issues.push({
            title: 'Insecure External Links',
            description: `Found ${advancedSecurityInfo.insecureLinks.length} links to external sites that use 'target="_blank"' without 'rel="noopener noreferrer"', which can lead to tab-nabbing attacks.`,
            remediation: 'Add `rel="noopener noreferrer"` to all links that open in a new tab.'
        });
        score -= advancedSecurityInfo.insecureLinks.length * 2;
    }

    // 6. Check for CSRF vulnerabilities
    if (domInfo && domInfo.forms) {
        domInfo.forms.forEach(form => {
            if (form.method === 'POST') {
                const hasCsrfToken = form.inputs.some(input => 
                    input.is_hidden &&
                    /csrf|token|auth/i.test(input.name) &&
                    input.value && input.value.length > 16
                );
                if (!hasCsrfToken) {
                    issues.push({
                        title: 'Potential CSRF Vulnerability',
                        description: `The form submitting to '${form.action}' appears to be missing an anti-CSRF token.`,
                        remediation: 'Implement anti-CSRF tokens (e.g., using a hidden input field with a unique, server-generated token) to ensure that state-changing requests are legitimate.'
                    });
                    score -= 10;
                }
            }
        });
    }

    // 7. Check for weak input validation
    if (domInfo && domInfo.forms) {
        domInfo.forms.forEach(form => {
            form.inputs.forEach(input => {
                // Check for missing 'required' on important fields
                if (/user|email|pass/i.test(input.name) && !input.required) {
                    issues.push({
                        title: 'Missing `required` Attribute',
                        description: `The input field '${input.name}' seems important but is missing the 'required' attribute, which can lead to submission of empty forms.`,
                        remediation: `Add the 'required' attribute to the input field '${input.name}' to enforce client-side validation.`
                    });
                    score -= 2;
                }

                // Check for weak password validation
                if (input.type === 'password' && !input.pattern) {
                    issues.push({
                        title: 'Weak Password Policy',
                        description: `The password field '${input.name}' does not have a 'pattern' attribute to enforce password complexity.`,
                        remediation: 'Add a `pattern` attribute with a regex to enforce a strong password policy (e.g., minimum length, uppercase, lowercase, numbers, special characters).'
                    });
                    score -= 3;
                }
            });
        });
    }

    // 8. Check for potential XSS and SQLi vulnerabilities
    if (domInfo && domInfo.forms) {
        const vulnerabilityReport = await checkVulnerabilities(url, domInfo.forms);
        issues.push(...vulnerabilityReport.issues);
        score -= vulnerabilityReport.scorePenalty;
    }

    return { score: Math.max(0, score), issues };
}

async function checkVulnerabilities(url, forms) {
    const issues = [];
    let scorePenalty = 0;

    const xssPayloads = {
        basic: '<script>alert("xss-test");</script>',
        img: '<img src=x onerror=alert("xss-test")>',
    };
    const sqliPayloads = {
        classic: "' OR 1=1 --",
        errorBased: "'",
    };

    for (const form of forms) {
        for (const input of form.inputs) {
            if (!['text', 'textarea', 'password', 'email', 'search', 'url'].includes(input.type) || !input.name) continue;

            // Test for XSS
            for (const [type, payload] of Object.entries(xssPayloads)) {
                try {
                    let responseText = '';
                    if (form.method === 'POST') {
                        const formData = new URLSearchParams();
                        form.inputs.forEach(i => formData.append(i.name, i.value));
                        formData.set(input.name, payload);
                        const response = await fetch(form.action || url, { method: 'POST', body: formData });
                        responseText = await response.text();
                    } else {
                        const testUrl = new URL(form.action || url);
                        testUrl.searchParams.set(input.name, payload);
                        const response = await fetch(testUrl);
                        responseText = await response.text();
                    }

                    if (responseText.includes(payload)) {
                        issues.push({
                            title: `Potential Reflected XSS (${type})`,
                            description: `The parameter '${input.name}' seems to be vulnerable to XSS. The payload was reflected in the page without proper output encoding.`,
                            remediation: 'Sanitize all user input on the server-side and apply context-aware output encoding on the client-side. For example, use libraries like DOMPurify before rendering user-provided content.'
                        });
                        scorePenalty += 15;
                        break; // Move to next input after finding one XSS
                    }
                } catch (e) { /* Ignore fetch errors */ }
            }

            // Test for SQLi
            for (const [type, payload] of Object.entries(sqliPayloads)) {
                try {
                    let responseText = '';
                    if (form.method === 'POST') {
                        const formData = new URLSearchParams();
                        form.inputs.forEach(i => formData.append(i.name, i.value));
                        formData.set(input.name, payload);
                        const response = await fetch(form.action || url, { method: 'POST', body: formData });
                        responseText = await response.text();
                    } else {
                        const testUrl = new URL(form.action || url);
                        testUrl.searchParams.set(input.name, payload);
                        const response = await fetch(testUrl);
                        responseText = await response.text();
                    }

                    if (/(sql|syntax|database|error|unclosed quotation mark)/i.test(responseText)) {
                        issues.push({
                            title: `Potential SQL Injection (${type})`,
                            description: `The parameter '${input.name}' may be vulnerable to SQL Injection. The application's response to a malicious payload suggests that user input is not being properly sanitized before being used in a database query.`,
                            remediation: 'Use parameterized queries (prepared statements) for all database interactions. Avoid building SQL queries by concatenating strings with user input.'
                        });
                        scorePenalty += 20;
                        break; // Move to next input after finding one SQLi
                    }
                } catch (e) { /* Ignore fetch errors */ }
            }
        }
    }
    return { issues, scorePenalty };
}

async function checkPerformance(performanceInfo) {
    const issues = [];
    let score = 100;
    const { resources, loadTime, oversizedImages, renderBlockingResources } = performanceInfo;

    // 1. Check page load speed
    if (loadTime > 3000) { // Slower than 3 seconds
        issues.push(`Performance: Page load time is slow (${(loadTime / 1000).toFixed(2)}s). Aim for < 3s.`);
        score -= 20;
    } else if (loadTime > 0) {
        issues.push(`Info: Page load time is ${(loadTime / 1000).toFixed(2)}s.`);
    }

    // 2. Identify large resources
    const largeResources = resources.filter(r => r.size > 150 * 1024); // > 150KB
    if (largeResources.length > 0) {
        issues.push(`Performance: Found ${largeResources.length} resources larger than 150KB.`);
        score -= largeResources.length * 4;
    }

    // 3. Check for oversized images
    if (oversizedImages && oversizedImages.length > 0) {
        issues.push(`Performance: Found ${oversizedImages.length} images that could be resized to save data.`);
        score -= oversizedImages.length * 5;
    }

    // 4. Check for render-blocking resources
    if (renderBlockingResources && renderBlockingResources.length > 0) {
        issues.push(`Performance: Found ${renderBlockingResources.length} render-blocking resources in the <head>.`);
        score -= renderBlockingResources.length * 5;
    }

    // 5. Check for unminified resources
    const unminified = resources.filter(r => 
        (r.type === 'script' || r.type === 'css') && 
        !r.name.includes('.min.') && 
        r.size > 20 * 1024 // Only check files > 20KB
    );
    if (unminified.length > 0) {
        issues.push(`Performance: Found ${unminified.length} JS/CSS files that could be minified.`);
        score -= unminified.length * 3;
    }

    if (score === 100 && issues.length <= 1) {
        issues.push('No major performance issues found.');
    }
    
    return { score: Math.max(0, score), issues };
}

async function checkSeo(url, { seoInfo }) {
    const issues = [];
    let score = 100;
    const origin = new URL(url).origin;

    // 1. Check for missing meta tags
    if (!seoInfo.title) {
        issues.push('SEO: Page is missing a title tag.');
        score -= 15;
    }
    if (!seoInfo.description) {
        issues.push('SEO: Page is missing a meta description.');
        score -= 10;
    }

    // 2. Check H1 tag usage
    if (seoInfo.h1Count === 0) {
        issues.push('SEO: Page is missing an H1 tag.');
        score -= 15;
    } else if (seoInfo.h1Count > 1) {
        issues.push(`SEO: Page has ${seoInfo.h1Count} H1 tags. There should only be one.`);
        score -= 10;
    }

    // 3. Check for missing alt attributes on images
    if (seoInfo.missingAltImages > 0) {
        issues.push(`SEO: Found ${seoInfo.missingAltImages} images missing an 'alt' attribute.`);
        score -= seoInfo.missingAltImages * 2;
    }

    // 4. Link Analysis
    const genericLinkTexts = ['click here', 'read more', 'learn more', 'here', 'link'];
    const nonDescriptiveLinks = seoInfo.links.filter(link => genericLinkTexts.includes(link.text.toLowerCase()));
    if (nonDescriptiveLinks.length > 0) {
        issues.push(`SEO: Found ${nonDescriptiveLinks.length} links with generic anchor text.`);
        score -= nonDescriptiveLinks.length * 2;
    }

    // 5. Check for broken internal links (sample a few)
    const internalLinks = seoInfo.links.filter(link => link.href && link.href.startsWith(origin));
    for (const link of internalLinks.slice(0, 5)) { // Check up to 5 links
        try {
            const res = await fetch(link.href, { method: 'HEAD' });
            if (!res.ok) {
                issues.push(`SEO: Found a potentially broken internal link: ${link.href} (status: ${res.status}).`);
                score -= 5;
            }
        } catch (e) { /* Ignore fetch errors */ }
    }

    // 6. Check for robots.txt and sitemap.xml
    try {
        if (!(await fetch(`${origin}/robots.txt`)).ok) {
            issues.push('SEO: robots.txt file not found.');
            score -= 5;
        }
    } catch (e) { issues.push('SEO: Could not check for robots.txt.'); }

    try {
        if (!(await fetch(`${origin}/sitemap.xml`)).ok) {
            issues.push('SEO: sitemap.xml file not found.');
            score -= 5;
        }
    } catch (e) { issues.push('SEO: Could not check for sitemap.xml.'); }

    if (score === 100 && issues.length === 0) {
        issues.push('No major SEO issues found.');
    }

    return { score: Math.max(0, score), issues };
}

async function getAuditHistory() {
    const result = await browser.storage.local.get('auditHistory');
    return result.auditHistory || {};
}

async function saveAuditReport(url, report) {
    const history = await getAuditHistory();
    const reportId = `audit_${Date.now()}`;
    history[reportId] = {
        url,
        report,
        date: new Date().toISOString(),
    };
    await browser.storage.local.set({ auditHistory: history });
}

async function checkAccessibility({ accessibilityInfo }) {
    const issues = [];
    let score = 100;

    // 1. Check for missing lang attribute
    if (accessibilityInfo.langMissing) {
        issues.push('Accessibility: The `lang` attribute is missing from the `<html>` tag.');
        score -= 15;
    }

    // 2. Check for missing form labels
    if (accessibilityInfo.missingFormLabels > 0) {
        issues.push(`Accessibility: Found ${accessibilityInfo.missingFormLabels} form elements missing labels.`);
        score -= accessibilityInfo.missingFormLabels * 5;
    }

    // 3. Check for missing ARIA labels
    if (accessibilityInfo.missingAriaLabels > 0) {
        issues.push(`Accessibility: Found ${accessibilityInfo.missingAriaLabels} elements with roles missing ARIA labels.`);
        score -= accessibilityInfo.missingAriaLabels * 4;
    }

    // 4. Check for invalid ARIA roles
    if (accessibilityInfo.invalidAriaRolesCount > 0) {
        issues.push(`Accessibility: Found ${accessibilityInfo.invalidAriaRolesCount} elements with invalid ARIA roles.`);
        score -= accessibilityInfo.invalidAriaRolesCount * 4;
    }

    if (score === 100 && issues.length === 0) {
        issues.push('No major accessibility issues found.');
    }

    issues.push('Info: Contrast ratios and keyboard navigation require manual review and were not automatically checked.');

    return { score: Math.max(0, score), issues };
}
