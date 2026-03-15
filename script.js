<<<<<<< HEAD
/**
 * Phishing Detection System
 * Analyzes URLs for potential phishing indicators
 */
// ============================================
// Configuration
// ============================================
const CONFIG = {
    // Keywords commonly found in phishing URLs
    suspiciousKeywords: [
        'login', 'signin', 'sign-in', 'verify', 'verification', 'secure',
        'update', 'confirm', 'account', 'password', 'banking', 'wallet',
        'authenticate', 'validate', 'suspend', 'unusual', 'activity',
        'limited', 'expire', 'urgent', 'immediately', 'click'
    ],
    // Known brand names often targeted
    targetedBrands: [
        'google', 'facebook', 'apple', 'microsoft', 'amazon', 'paypal',
        'netflix', 'instagram', 'twitter', 'linkedin', 'dropbox', 'adobe',
        'spotify', 'steam', 'chase', 'wellsfargo', 'bankofamerica'
    ],
    // Common typosquatting patterns
    typoPatterns: [
        { original: 'o', fake: '0' },
        { original: 'l', fake: '1' },
        { original: 'i', fake: '1' },
        { original: 'e', fake: '3' },
        { original: 'a', fake: '4' },
        { original: 's', fake: '5' },
        { original: 'g', fake: '9' }
    ],
    // Suspicious TLDs often used in phishing
    suspiciousTLDs: [
        'xyz', 'top', 'club', 'online', 'site', 'website', 'space',
        'info', 'click', 'link', 'work', 'tk', 'ml', 'ga', 'cf', 'gq'
    ],
    // Trusted TLDs (lower risk)
    trustedTLDs: ['com', 'org', 'net', 'edu', 'gov', 'co', 'io']
};
// ============================================
// DOM Elements
// ============================================
const elements = {
    urlInput: document.getElementById('url-input'),
    scanBtn: document.getElementById('scan-btn'),
    resultSection: document.getElementById('result-section'),
    meterCircle: document.getElementById('meter-circle'),
    scoreValue: document.getElementById('score-value'),
    riskBadge: document.getElementById('risk-badge'),
    analyzedUrl: document.getElementById('analyzed-url'),
    findingsList: document.getElementById('findings-list'),
    exampleBtns: document.querySelectorAll('.example-btn'),
    clearBtn: document.getElementById('clear-btn')
};
// ============================================
// Event Listeners
// ============================================
elements.scanBtn.addEventListener('click', handleScan);
elements.urlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') handleScan();
});
elements.exampleBtns.forEach(btn => {
    btn.addEventListener('click', () => {
        elements.urlInput.value = btn.dataset.url;
        handleScan();
    });
});
elements.clearBtn.addEventListener('click', () => {
    elements.urlInput.value = '';
    elements.urlInput.focus();
    elements.resultSection.classList.add('hidden');
});
// ============================================
// Main Functions
// ============================================
async function handleScan() {
    const url = elements.urlInput.value.trim();
    if (!url) {
        shakeInput();
        return;
    }
    // Add loading state
    elements.scanBtn.classList.add('loading');
    // Simulate processing delay for better UX
    await sleep(800);
    // Analyze the URL
    const result = analyzeUrl(url);
    // Display results
    displayResults(result);
    // Remove loading state
    elements.scanBtn.classList.remove('loading');
}
function analyzeUrl(url) {
    const findings = [];
    let riskScore = 0;
    // Normalize URL
    let normalizedUrl = url.toLowerCase();
    if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
        normalizedUrl = 'https://' + normalizedUrl;
    }
    let parsedUrl;
    try {
        parsedUrl = new URL(normalizedUrl);
    } catch (e) {
        return {
            url: url,
            score: 50,
            level: 'medium',
            findings: [{
                type: 'negative',
                icon: '❌',
                text: 'URL ไม่ถูกต้อง - ไม่สามารถวิเคราะห์ได้'
            }]
        };
    }
    const hostname = parsedUrl.hostname;
    const pathname = parsedUrl.pathname;
    const fullUrl = parsedUrl.href;
    // ========================================
    // Check 1: HTTPS
    // ========================================
    if (parsedUrl.protocol === 'https:') {
        findings.push({
            type: 'positive',
            icon: '🔒',
            text: 'ใช้ HTTPS - การเชื่อมต่อเข้ารหัส'
        });
    } else {
        riskScore += 15;
        findings.push({
            type: 'negative',
            icon: '🔓',
            text: 'ไม่ใช้ HTTPS - การเชื่อมต่อไม่ปลอดภัย'
        });
    }
    // ========================================
    // Check 2: IP Address instead of domain
    // ========================================
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipPattern.test(hostname)) {
        riskScore += 30;
        findings.push({
            type: 'negative',
            icon: '🔢',
            text: 'ใช้ IP Address แทนชื่อโดเมน - พฤติกรรมน่าสงสัย'
        });
    }
    // ========================================
    // Check 3: Suspicious TLD
    // ========================================
    const tld = hostname.split('.').pop();
    if (CONFIG.suspiciousTLDs.includes(tld)) {
        riskScore += 20;
        findings.push({
            type: 'warning',
            icon: '🌐',
            text: `ใช้ TLD ที่มีความเสี่ยง (.${tld}) - มักพบในฟิชชิ่ง`
        });
    } else if (CONFIG.trustedTLDs.includes(tld)) {
        findings.push({
            type: 'positive',
            icon: '✅',
            text: `ใช้ TLD ที่น่าเชื่อถือ (.${tld})`
        });
    }
    // ========================================
    // Check 4: Too many subdomains
    // ========================================
    const subdomains = hostname.split('.').length - 2;
    if (subdomains > 2) {
        riskScore += 15;
        findings.push({
            type: 'warning',
            icon: '📊',
            text: `มี subdomain มากเกินไป (${subdomains} ระดับ) - อาจใช้ซ่อน domain จริง`
        });
    }
    // ========================================
    // Check 5: URL length
    // ========================================
    if (fullUrl.length > 100) {
        riskScore += 10;
        findings.push({
            type: 'warning',
            icon: '📏',
            text: `URL ยาวผิดปกติ (${fullUrl.length} ตัวอักษร)`
        });
    }
    // ========================================
    // Check 6: Suspicious keywords
    // ========================================
    const foundKeywords = [];
    CONFIG.suspiciousKeywords.forEach(keyword => {
        if (fullUrl.includes(keyword)) {
            foundKeywords.push(keyword);
        }
    });
    if (foundKeywords.length > 0) {
        riskScore += Math.min(foundKeywords.length * 8, 25);
        findings.push({
            type: 'warning',
            icon: '⚠️',
            text: `พบคำน่าสงสัย: ${foundKeywords.join(', ')}`
        });
    }
    // ========================================
    // Check 7: Typosquatting
    // ========================================
    const typosquatResults = checkTyposquatting(hostname);
    if (typosquatResults.length > 0) {
        riskScore += 35;
        typosquatResults.forEach(result => {
            findings.push({
                type: 'negative',
                icon: '🎭',
                text: `Typosquatting: อาจเลียนแบบ "${result.brand}" (พบ: ${result.found})`
            });
        });
    }
    // ========================================
    // Check 8: Special characters in URL
    // ========================================
    const specialChars = ['@', '=', '&', '%', '//'];
    let foundSpecialChars = [];
    specialChars.forEach(char => {
        if (pathname.includes(char)) {
            foundSpecialChars.push(char);
        }
    });
    if (foundSpecialChars.length > 2) {
        riskScore += 10;
        findings.push({
            type: 'warning',
            icon: '🔣',
            text: 'มีตัวอักษรพิเศษมากในเส้นทาง URL'
        });
    }
    // ========================================
    // Check 9: Dash abuse in domain
    // ========================================
    const dashCount = (hostname.match(/-/g) || []).length;
    if (dashCount > 2) {
        riskScore += 15;
        findings.push({
            type: 'warning',
            icon: '➖',
            text: `มีเครื่องหมาย "-" มากเกินไปในโดเมน (${dashCount} ตัว)`
        });
    }
    // ========================================
    // Check 10: Known safe domains
    // ========================================
    const safeDomains = [
        'google.com', 'facebook.com', 'microsoft.com', 'apple.com', 'amazon.com',
        'youtube.com', 'github.com', 'twitter.com', 'instagram.com', 'linkedin.com',
        'wikipedia.org', 'stackoverflow.com', 'cloudflare.com', 'line.me', 'lazada.co.th',
        'shopee.co.th', 'scb.co.th', 'kasikornbank.com', 'krungthai.com'
    ];
    const isKnownSafe = safeDomains.some(domain => hostname === domain || hostname.endsWith('.' + domain));
    if (isKnownSafe) {
        riskScore = Math.max(0, riskScore - 40);
        findings.unshift({
            type: 'positive',
            icon: '🏢',
            text: 'เป็นโดเมนจากองค์กรที่รู้จักและน่าเชื่อถือ'
        });
    }
    // Cap the score at 100
    riskScore = Math.min(100, Math.max(0, riskScore));
    // Determine risk level
    let level;
    if (riskScore <= 15) level = 'safe';
    else if (riskScore <= 35) level = 'low';
    else if (riskScore <= 55) level = 'medium';
    else if (riskScore <= 75) level = 'high';
    else level = 'danger';
    return {
        url: fullUrl,
        score: riskScore,
        level: level,
        findings: findings
    };
}
function checkTyposquatting(hostname) {
    const results = [];
    const detectedBrands = new Set(); // ป้องกันการแจ้งเตือนแบรนด์เดียวกันซ้ำ
    CONFIG.targetedBrands.forEach(brand => {
        // ตรวจสอบว่าเป็นโดเมนจริงของแบรนด์หรือไม่
        const isRealDomain = hostname === brand + '.com' ||
            hostname === 'www.' + brand + '.com' ||
            hostname.endsWith('.' + brand + '.com') ||
            hostname === brand + '.co' ||
            hostname.endsWith('.' + brand + '.co');
        if (isRealDomain) return; // ข้ามถ้าเป็นโดเมนจริง
        // Check for typo variations (เช่น g00gle)
        CONFIG.typoPatterns.forEach(pattern => {
            if (detectedBrands.has(brand)) return;
            const typoVersion = brand.replace(new RegExp(pattern.original, 'g'), pattern.fake);
            if (typoVersion !== brand && hostname.includes(typoVersion)) {
                results.push({ brand: brand, found: typoVersion });
                detectedBrands.add(brand);
            }
        });
        // Check for brand name used inside subdomain (เช่น google-secure-login.com)
        if (!detectedBrands.has(brand) && hostname.includes(brand)) {
            // ต้องมีส่วนอื่นต่อท้ายด้วย ไม่ใช่แค่ brand.com
            const parts = hostname.split('.');
            const brandInNonTLD = parts.slice(0, -1).some(p => p.includes(brand));
            if (brandInNonTLD) {
                results.push({ brand: brand, found: 'ใช้ชื่อแบรนด์ใน URL อย่างน่าสงสัย' });
                detectedBrands.add(brand);
            }
        }
    });
    return results;
}
function displayResults(result) {
    // Show result section
    elements.resultSection.classList.remove('hidden');
    // Scroll to results
    elements.resultSection.scrollIntoView({ behavior: 'smooth', block: 'center' });
    // Update analyzed URL
    elements.analyzedUrl.textContent = result.url;
    // Animate score
    animateScore(result.score);
    // Update meter color based on level
    updateMeterColor(result.level, result.score);
    // Update risk badge
    updateRiskBadge(result.level);
    // Display findings
    displayFindings(result.findings);
}
function animateScore(targetScore) {
    let currentScore = 0;
    const duration = 1000;
    const startTime = performance.now();
    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        // Easing function
        const easeOut = 1 - Math.pow(1 - progress, 3);
        currentScore = Math.round(targetScore * easeOut);
        elements.scoreValue.textContent = currentScore;
        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }
    requestAnimationFrame(update);
}
function updateMeterColor(level, score) {
    const colors = {
        safe: '#10b981',
        low: '#22c55e',
        medium: '#f59e0b',
        high: '#f97316',
        danger: '#ef4444'
    };
    // Calculate stroke offset (534 is the full circumference)
    const offset = 534 - (534 * score / 100);
    elements.meterCircle.style.stroke = colors[level];
    elements.meterCircle.style.strokeDashoffset = offset;
    elements.scoreValue.style.color = colors[level];
}
function updateRiskBadge(level) {
    const badges = {
        safe: { icon: '✅', text: 'ปลอดภัย' },
        low: { icon: '🟢', text: 'เสี่ยงต่ำ' },
        medium: { icon: '🟡', text: 'เสี่ยงปานกลาง' },
        high: { icon: '🟠', text: 'เสี่ยงสูง' },
        danger: { icon: '🔴', text: 'อันตราย!' }
    };
    const badge = badges[level];
    elements.riskBadge.className = 'risk-badge ' + level;
    elements.riskBadge.innerHTML = `
        <span class="badge-icon">${badge.icon}</span>
        <span class="badge-text">${badge.text}</span>
    `;
}
function displayFindings(findings) {
    elements.findingsList.innerHTML = '';
    findings.forEach((finding, index) => {
        const item = document.createElement('div');
        item.className = `finding-item ${finding.type}`;
        item.style.animationDelay = `${index * 100}ms`;
        item.innerHTML = `
            <span class="finding-icon">${finding.icon}</span>
            <span class="finding-text">${finding.text}</span>
        `;
        elements.findingsList.appendChild(item);
    });
}
// ============================================
// Utility Functions
// ============================================
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
function shakeInput() {
    elements.urlInput.style.animation = 'shake 0.5s ease';
    elements.urlInput.style.borderColor = 'var(--risk-danger)';
    setTimeout(() => {
        elements.urlInput.style.animation = '';
        elements.urlInput.style.borderColor = '';
    }, 500);
}
// Add shake animation
const style = document.createElement('style');
style.textContent = `
    @keyframes shake {
        0%, 100% { transform: translateX(0); }
        20%, 60% { transform: translateX(-5px); }
        40%, 80% { transform: translateX(5px); }
    }
`;
document.head.appendChild(style);
=======
/**
 * Phishing Detection System
 * Analyzes URLs for potential phishing indicators
 */
// ============================================
// Configuration
// ============================================
const CONFIG = {
    // Keywords commonly found in phishing URLs
    suspiciousKeywords: [
        'login', 'signin', 'sign-in', 'verify', 'verification', 'secure',
        'update', 'confirm', 'account', 'password', 'banking', 'wallet',
        'authenticate', 'validate', 'suspend', 'unusual', 'activity',
        'limited', 'expire', 'urgent', 'immediately', 'click'
    ],
    // Known brand names often targeted
    targetedBrands: [
        'google', 'facebook', 'apple', 'microsoft', 'amazon', 'paypal',
        'netflix', 'instagram', 'twitter', 'linkedin', 'dropbox', 'adobe',
        'spotify', 'steam', 'chase', 'wellsfargo', 'bankofamerica'
    ],
    // Common typosquatting patterns
    typoPatterns: [
        { original: 'o', fake: '0' },
        { original: 'l', fake: '1' },
        { original: 'i', fake: '1' },
        { original: 'e', fake: '3' },
        { original: 'a', fake: '4' },
        { original: 's', fake: '5' },
        { original: 'g', fake: '9' }
    ],
    // Suspicious TLDs often used in phishing
    suspiciousTLDs: [
        'xyz', 'top', 'club', 'online', 'site', 'website', 'space',
        'info', 'click', 'link', 'work', 'tk', 'ml', 'ga', 'cf', 'gq'
    ],
    // Trusted TLDs (lower risk)
    trustedTLDs: ['com', 'org', 'net', 'edu', 'gov', 'co', 'io']
};
// ============================================
// DOM Elements
// ============================================
const elements = {
    urlInput: document.getElementById('url-input'),
    scanBtn: document.getElementById('scan-btn'),
    resultSection: document.getElementById('result-section'),
    meterCircle: document.getElementById('meter-circle'),
    scoreValue: document.getElementById('score-value'),
    riskBadge: document.getElementById('risk-badge'),
    analyzedUrl: document.getElementById('analyzed-url'),
    findingsList: document.getElementById('findings-list'),
    exampleBtns: document.querySelectorAll('.example-btn')
};
// ============================================
// Event Listeners
// ============================================
elements.scanBtn.addEventListener('click', handleScan);
elements.urlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') handleScan();
});
elements.exampleBtns.forEach(btn => {
    btn.addEventListener('click', () => {
        elements.urlInput.value = btn.dataset.url;
        handleScan();
    });
});
// ============================================
// Main Functions
// ============================================
async function handleScan() {
    const url = elements.urlInput.value.trim();
    if (!url) {
        shakeInput();
        return;
    }
    // Add loading state
    elements.scanBtn.classList.add('loading');
    // Simulate processing delay for better UX
    await sleep(800);
    // Analyze the URL
    const result = analyzeUrl(url);
    // Display results
    displayResults(result);
    // Remove loading state
    elements.scanBtn.classList.remove('loading');
}
function analyzeUrl(url) {
    const findings = [];
    let riskScore = 0;
    // Normalize URL
    let normalizedUrl = url.toLowerCase();
    if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
        normalizedUrl = 'https://' + normalizedUrl;
    }
    let parsedUrl;
    try {
        parsedUrl = new URL(normalizedUrl);
    } catch (e) {
        return {
            url: url,
            score: 50,
            level: 'medium',
            findings: [{
                type: 'negative',
                icon: '❌',
                text: 'URL ไม่ถูกต้อง - ไม่สามารถวิเคราะห์ได้'
            }]
        };
    }
    const hostname = parsedUrl.hostname;
    const pathname = parsedUrl.pathname;
    const fullUrl = parsedUrl.href;
    // ========================================
    // Check 1: HTTPS
    // ========================================
    if (parsedUrl.protocol === 'https:') {
        findings.push({
            type: 'positive',
            icon: '🔒',
            text: 'ใช้ HTTPS - การเชื่อมต่อเข้ารหัส'
        });
    } else {
        riskScore += 15;
        findings.push({
            type: 'negative',
            icon: '🔓',
            text: 'ไม่ใช้ HTTPS - การเชื่อมต่อไม่ปลอดภัย'
        });
    }
    // ========================================
    // Check 2: IP Address instead of domain
    // ========================================
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipPattern.test(hostname)) {
        riskScore += 30;
        findings.push({
            type: 'negative',
            icon: '🔢',
            text: 'ใช้ IP Address แทนชื่อโดเมน - พฤติกรรมน่าสงสัย'
        });
    }
    // ========================================
    // Check 3: Suspicious TLD
    // ========================================
    const tld = hostname.split('.').pop();
    if (CONFIG.suspiciousTLDs.includes(tld)) {
        riskScore += 20;
        findings.push({
            type: 'warning',
            icon: '🌐',
            text: `ใช้ TLD ที่มีความเสี่ยง (.${tld}) - มักพบในฟิชชิ่ง`
        });
    } else if (CONFIG.trustedTLDs.includes(tld)) {
        findings.push({
            type: 'positive',
            icon: '✅',
            text: `ใช้ TLD ที่น่าเชื่อถือ (.${tld})`
        });
    }
    // ========================================
    // Check 4: Too many subdomains
    // ========================================
    const subdomains = hostname.split('.').length - 2;
    if (subdomains > 2) {
        riskScore += 15;
        findings.push({
            type: 'warning',
            icon: '📊',
            text: `มี subdomain มากเกินไป (${subdomains} ระดับ) - อาจใช้ซ่อน domain จริง`
        });
    }
    // ========================================
    // Check 5: URL length
    // ========================================
    if (fullUrl.length > 100) {
        riskScore += 10;
        findings.push({
            type: 'warning',
            icon: '📏',
            text: `URL ยาวผิดปกติ (${fullUrl.length} ตัวอักษร)`
        });
    }
    // ========================================
    // Check 6: Suspicious keywords
    // ========================================
    const foundKeywords = [];
    CONFIG.suspiciousKeywords.forEach(keyword => {
        if (fullUrl.includes(keyword)) {
            foundKeywords.push(keyword);
        }
    });
    if (foundKeywords.length > 0) {
        riskScore += Math.min(foundKeywords.length * 8, 25);
        findings.push({
            type: 'warning',
            icon: '⚠️',
            text: `พบคำน่าสงสัย: ${foundKeywords.join(', ')}`
        });
    }
    // ========================================
    // Check 7: Typosquatting
    // ========================================
    const typosquatResults = checkTyposquatting(hostname);
    if (typosquatResults.length > 0) {
        riskScore += 35;
        typosquatResults.forEach(result => {
            findings.push({
                type: 'negative',
                icon: '🎭',
                text: `Typosquatting: อาจเลียนแบบ "${result.brand}" (พบ: ${result.found})`
            });
        });
    }
    // ========================================
    // Check 8: Special characters in URL
    // ========================================
    const specialChars = ['@', '=', '&', '%', '//'];
    let foundSpecialChars = [];
    specialChars.forEach(char => {
        if (pathname.includes(char)) {
            foundSpecialChars.push(char);
        }
    });
    if (foundSpecialChars.length > 2) {
        riskScore += 10;
        findings.push({
            type: 'warning',
            icon: '🔣',
            text: 'มีตัวอักษรพิเศษมากในเส้นทาง URL'
        });
    }
    // ========================================
    // Check 9: Dash abuse in domain
    // ========================================
    const dashCount = (hostname.match(/-/g) || []).length;
    if (dashCount > 2) {
        riskScore += 15;
        findings.push({
            type: 'warning',
            icon: '➖',
            text: `มีเครื่องหมาย "-" มากเกินไปในโดเมน (${dashCount} ตัว)`
        });
    }
    // ========================================
    // Check 10: Known safe domains
    // ========================================
    const safeDomains = ['google.com', 'facebook.com', 'microsoft.com', 'apple.com', 'amazon.com'];
    const isKnownSafe = safeDomains.some(domain => hostname === domain || hostname.endsWith('.' + domain));
    if (isKnownSafe) {
        riskScore = Math.max(0, riskScore - 30);
        findings.unshift({
            type: 'positive',
            icon: '🏢',
            text: 'เป็นโดเมนจากบริษัทที่รู้จักและน่าเชื่อถือ'
        });
    }
    // Cap the score at 100
    riskScore = Math.min(100, Math.max(0, riskScore));
    // Determine risk level
    let level;
    if (riskScore <= 10) level = 'safe';
    else if (riskScore <= 30) level = 'low';
    else if (riskScore <= 50) level = 'medium';
    else if (riskScore <= 75) level = 'high';
    else level = 'danger';
    return {
        url: fullUrl,
        score: riskScore,
        level: level,
        findings: findings
    };
}
function checkTyposquatting(hostname) {
    const results = [];
    CONFIG.targetedBrands.forEach(brand => {
        // Check for typo variations
        CONFIG.typoPatterns.forEach(pattern => {
            const typoVersion = brand.replace(new RegExp(pattern.original, 'g'), pattern.fake);
            if (hostname.includes(typoVersion) && !hostname.includes(brand)) {
                results.push({
                    brand: brand,
                    found: typoVersion
                });
            }
        });
        // Check for brand name in subdomain (suspicious pattern)
        if (hostname.includes(brand) && !hostname.endsWith(brand + '.com') && !hostname.endsWith(brand + '.co')) {
            // Check if it's not the real domain
            const isRealDomain = hostname === brand + '.com' ||
                hostname.endsWith('.' + brand + '.com');
            if (!isRealDomain) {
                results.push({
                    brand: brand,
                    found: 'ใช้ชื่อแบรนด์ใน subdomain'
                });
            }
        }
    });
    return results;
}
function displayResults(result) {
    // Show result section
    elements.resultSection.classList.remove('hidden');
    // Scroll to results
    elements.resultSection.scrollIntoView({ behavior: 'smooth', block: 'center' });
    // Update analyzed URL
    elements.analyzedUrl.textContent = result.url;
    // Animate score
    animateScore(result.score);
    // Update meter color based on level
    updateMeterColor(result.level, result.score);
    // Update risk badge
    updateRiskBadge(result.level);
    // Display findings
    displayFindings(result.findings);
}
function animateScore(targetScore) {
    let currentScore = 0;
    const duration = 1000;
    const startTime = performance.now();
    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        // Easing function
        const easeOut = 1 - Math.pow(1 - progress, 3);
        currentScore = Math.round(targetScore * easeOut);
        elements.scoreValue.textContent = currentScore;
        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }
    requestAnimationFrame(update);
}
function updateMeterColor(level, score) {
    const colors = {
        safe: '#10b981',
        low: '#22c55e',
        medium: '#f59e0b',
        high: '#f97316',
        danger: '#ef4444'
    };
    // Calculate stroke offset (534 is the full circumference)
    const offset = 534 - (534 * score / 100);
    elements.meterCircle.style.stroke = colors[level];
    elements.meterCircle.style.strokeDashoffset = offset;
    elements.scoreValue.style.color = colors[level];
}
function updateRiskBadge(level) {
    const badges = {
        safe: { icon: '✅', text: 'ปลอดภัย' },
        low: { icon: '🟢', text: 'เสี่ยงต่ำ' },
        medium: { icon: '🟡', text: 'เสี่ยงปานกลาง' },
        high: { icon: '🟠', text: 'เสี่ยงสูง' },
        danger: { icon: '🔴', text: 'อันตราย!' }
    };
    const badge = badges[level];
    elements.riskBadge.className = 'risk-badge ' + level;
    elements.riskBadge.innerHTML = `
        <span class="badge-icon">${badge.icon}</span>
        <span class="badge-text">${badge.text}</span>
    `;
}
function displayFindings(findings) {
    elements.findingsList.innerHTML = '';
    findings.forEach((finding, index) => {
        const item = document.createElement('div');
        item.className = `finding-item ${finding.type}`;
        item.style.animationDelay = `${index * 100}ms`;
        item.innerHTML = `
            <span class="finding-icon">${finding.icon}</span>
            <span class="finding-text">${finding.text}</span>
        `;
        elements.findingsList.appendChild(item);
    });
}
// ============================================
// Utility Functions
// ============================================
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
function shakeInput() {
    elements.urlInput.style.animation = 'shake 0.5s ease';
    elements.urlInput.style.borderColor = 'var(--risk-danger)';
    setTimeout(() => {
        elements.urlInput.style.animation = '';
        elements.urlInput.style.borderColor = '';
    }, 500);
}
// Add shake animation
const style = document.createElement('style');
style.textContent = `
    @keyframes shake {
        0%, 100% { transform: translateX(0); }
        20%, 60% { transform: translateX(-5px); }
        40%, 80% { transform: translateX(5px); }
    }
`;
document.head.appendChild(style);
>>>>>>> 5f2a8d7527a1d787d7545ee9c38ddc1fa86bc8be
