// Content script for website audit tool
console.log('Content script loaded on:', window.location.href);

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    console.log('Content script received message:', message);
    
    if (message.action === "getDOMInfo") {
        const forms = Array.from(document.querySelectorAll('form')).map(form => ({
            action: form.action,
            method: form.method.toUpperCase() || 'GET',
            inputs: Array.from(form.querySelectorAll('input, textarea, select')).map(input => ({
                name: input.name || input.id,
                value: input.value,
                type: input.type,
                required: input.required,
                pattern: input.pattern,
                is_hidden: input.type === 'hidden'
            }))
        }));
        sendResponse({ forms });

    } else if (message.action === "getPerformanceInfo") {
        const perfData = performance.getEntriesByType('navigation')[0];
        const resources = performance.getEntriesByType('resource').map(r => ({
            name: r.name,
            size: r.transferSize || 0,
            duration: r.duration,
            type: r.initiatorType
        }));

        const oversizedImages = Array.from(document.querySelectorAll('img')).filter(img =>
            img.naturalWidth > 0 &&
            img.clientWidth > 0 &&
            (img.naturalWidth > img.clientWidth * 1.5) // 50% larger than rendered size
        ).map(img => img.src);

        const renderBlockingScripts = Array.from(document.querySelectorAll('head > script[src]:not([async]):not([defer])'))
            .map(script => script.src);

        const renderBlockingStyles = Array.from(document.querySelectorAll('head > link[rel="stylesheet"]:not([media="print"]):not([media="aural"])'))
            .map(link => link.href);

        sendResponse({
            loadTime: perfData ? perfData.loadEventEnd - perfData.fetchStart : 0,
            resources,
            oversizedImages,
            renderBlockingResources: [...renderBlockingScripts, ...renderBlockingStyles]
        });

    } else if (message.action === "getSeoInfo") {
        const links = Array.from(document.querySelectorAll('a')).map(a => ({
            href: a.href,
            text: a.innerText.trim()
        }));

        sendResponse({
            seoInfo: {
                title: document.title,
                description: document.querySelector('meta[name="description"]')?.content || '',
                keywords: document.querySelector('meta[name="keywords"]')?.content || '',
                missingAltImages: document.querySelectorAll('img:not([alt=""])').length,
                h1Count: document.getElementsByTagName('h1').length,
                links: links
            }
        });

    } else if (message.action === "getAccessibilityInfo") {
        const inputs = document.querySelectorAll('input:not([type="hidden"]):not([type="submit"]), textarea, select');
        let missingFormLabels = 0;
        inputs.forEach(input => {
            if (input.id && document.querySelector(`label[for="${input.id}"]`)) return;
            if (input.closest('label')) return;
            missingFormLabels++;
        });

        const validAriaRoles = ['alert', 'button', 'checkbox', 'dialog', 'gridcell', 'link', 'log', 'marquee', 'menuitem', 'menuitemcheckbox', 'menuitemradio', 'option', 'progressbar', 'radio', 'scrollbar', 'searchbox', 'slider', 'spinbutton', 'status', 'switch', 'tab', 'tabpanel', 'textbox', 'timer', 'tooltip', 'treeitem'];
        const invalidRoles = Array.from(document.querySelectorAll('[role]'))
            .map(el => el.getAttribute('role').toLowerCase())
            .filter(role => !validAriaRoles.includes(role));

        sendResponse({
            accessibilityInfo: {
                missingFormLabels,
                missingAriaLabels: document.querySelectorAll('[role]:not([aria-label],[aria-labelledby])').length,
                langMissing: !document.documentElement.lang,
                invalidAriaRolesCount: invalidRoles.length
            }
        });

    } else if (message.action === "getAdvancedSecurityInfo") {
        const isHttps = window.location.protocol === 'https:';
        let mixedContent = [];
        if (isHttps) {
            mixedContent = Array.from(document.querySelectorAll('img[src^="http:"], script[src^="http:"], link[href^="http:"]'))
                .map(el => el.src || el.href);
        }

        const insecureLinks = Array.from(document.querySelectorAll('a[target="_blank"]:not([rel*="noopener"])'))
            .map(a => a.href);

        sendResponse({ mixedContent, insecureLinks });
    }

    return true; // Keep the message channel open for async response
});
