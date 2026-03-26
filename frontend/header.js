async function loadHeader() {
    try {
        const response = await fetch('header.html');
        const text = await response.text();

        // Insert header at start of body
        document.body.insertAdjacentHTML('afterbegin', text);

        // Initialize Lucide icons
        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }





        // Active Link Logic
        const currentPath = window.location.pathname.split('/').pop() || 'homepage.html';
        const navLinks = document.querySelectorAll('.nav-link');

        navLinks.forEach(link => {
            const linkHref = link.getAttribute('href');
            if (linkHref === currentPath) {
                link.classList.add('text-indigo-400', 'border-b-2', 'border-indigo-400');
                link.classList.remove('text-gray-300');
            }
        });

        // Logout & Profile Button Logic
        const token = localStorage.getItem('token');
        if (token) {
            const logoutBtn = document.getElementById('logout-btn');
            if (logoutBtn) logoutBtn.classList.remove('hidden');

            // Decode Token to get Email/User Initial
            try {
                const payload = JSON.parse(atob(token.split('.')[1]));
                const initial = payload.email ? payload.email.charAt(0).toUpperCase() : "U";

                const profileBtn = document.getElementById('profile-btn');
                const profileContainer = document.getElementById('profile-btn-container');
                if (profileBtn) {
                    profileBtn.textContent = initial;
                    if (profileContainer) profileContainer.classList.remove('hidden');
                    else profileBtn.classList.remove('hidden');
                }
            } catch (e) {
                console.error("Token decode error:", e);
            }
        }

        // Inject Link Guard Modals
        // injectLinkGuardModals();

        // Initialize Link Guard
        // initializeLinkGuard();

        // 🟢 LOG PAGE VIEW
        logPageView();

    } catch (err) {
        console.error('Error loading header:', err);
    }

    // Inject Global Chatbot
    injectChatbot();
}

function injectChatbot() {
    // 0. Exclude from specific pages
    if (window.location.pathname.includes('detectors.html')) return;

    // 1. Check if chatbot already exists to prevent duplicates
    if (document.getElementById('chatbot-root-btn')) return;

    // 2. Chatbot HTML Structure
    const chatbotHTML = `
        <div id="chatbot-wrapper" class="hidden fixed inset-0 z-[9999] bg-black/60 backdrop-blur-sm">
            <div class="absolute inset-0" onclick="toggleChat()"></div>
            <iframe src="chatboat.html" id="chat-iframe"
                class="absolute right-0 top-0 w-full sm:w-[500px] h-full border-l border-white/10 translate-x-full transition-transform duration-300"></iframe>
        </div>

        <div class="fixed bottom-8 right-12 z-[10000] flex items-center gap-3 group">
            <!-- Tooltip Message -->
            <div class="bg-white/90 backdrop-blur text-slate-900 px-4 py-2 rounded-l-2xl rounded-tr-2xl shadow-xl opacity-0 translate-x-4 group-hover:opacity-100 group-hover:translate-x-0 transition-all duration-300 pointer-events-none font-bold text-sm whitespace-nowrap">
                Hi! Need Help? 👋
            </div>

            <button id="chatbot-root-btn" onclick="toggleChat()"
                class="w-16 h-16 bg-indigo-600 rounded-2xl flex items-center justify-center shadow-2xl hover:scale-110 transition-transform duration-300 border border-white/10 animate-bounce">
                <!-- Cute Robot with Hi Bubble -->
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" class="w-10 h-10">
                    <!-- Head -->
                    <rect x="25" y="35" width="50" height="40" rx="12" ry="12" fill="white"/>
                    <!-- Eyes -->
                    <circle cx="40" cy="50" r="4" fill="#0ea5e9"/>
                    <circle cx="60" cy="50" r="4" fill="#0ea5e9"/>
                    <!-- Antenna -->
                    <line x1="50" y1="35" x2="50" y2="25" stroke="white" stroke-width="3" stroke-linecap="round"/>
                    <circle cx="50" cy="22" r="3" fill="white"/>
                    <!-- Body -->
                    <path d="M30 75 Q50 85 70 75 V85 H30 Z" fill="white"/>
                    <!-- Speech Bubble -->
                    <path d="M70 20 H90 A5 5 0 0 1 95 25 V45 A5 5 0 0 1 90 50 H80 L70 60 V50 H70 A5 5 0 0 1 65 45 V25 A5 5 0 0 1 70 20 Z" fill="#06b6d4"/>
                    <!-- Text HI! -->
                    <path d="M74 30 V40 M74 35 H80 M80 30 V40 M86 30 V38 M86 41 V42" stroke="white" stroke-width="2.5" stroke-linecap="round"/>
                </svg>
            </button>
        </div>
    `;

    // 3. Append to Body
    document.body.insertAdjacentHTML('beforeend', chatbotHTML);
}

// Global Toggle Function
window.toggleChat = function () {
    const wrapper = document.getElementById('chatbot-wrapper');
    const iframe = document.getElementById('chat-iframe');

    if (wrapper.classList.contains('hidden')) {
        wrapper.classList.remove('hidden');
        // Small delay to allow display:block to apply before transition
        setTimeout(() => {
            iframe.classList.remove('translate-x-full');
        }, 10);
    } else {
        iframe.classList.add('translate-x-full');
        // Wait for transition to finish before hiding
        setTimeout(() => {
            wrapper.classList.add('hidden');
        }, 300);
    }
};

async function logPageView() {
    const pageMap = {
        'homepage.html': 'Opened Homepage',
        'index.html': 'Opened Homepage',
        'news.html': 'Read Latest Cyber News',
        'report.html': 'Viewed Security Reports',
        'quizzes.html': 'Browsed Security Quizzes',
        'detectors.html': 'Visited Detection Dashboard',
        'awareness.html': 'Viewed Awareness Content',
        'my_account.html': 'Viewed Personal Profile',
        'scam_pattern.html': 'Browsed Scam Intelligence',
        'toolkit.html': 'Visited Cyber Toolkit'
    };

    const currentPath = window.location.pathname.split('/').pop() || 'index.html';
    const action = pageMap[currentPath] || `Viewed ${currentPath.replace('.html', '').replace('_', ' ').replace('-', ' ').toUpperCase()} Page`;

    const token = localStorage.getItem('token');

    try {
        await fetch(`${CONFIG.API_BASE_URL}/api/activity/log`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': token ? `Bearer ${token}` : ''
            },
            body: JSON.stringify({ action: action })
        });
    } catch (err) {
        console.error("Failed to log page view:", err);
    }
}

function logoutUser() {
    localStorage.clear();
    window.location.replace("login.html");
}



// ========================================
// LINK GUARD: INJECT MODALS
// ========================================
function injectLinkGuardModals() {
    const modalsHTML = `
        <!-- Link Guard Scan Overlay -->
        <div id="linkGuardScanOverlay" class="fixed inset-0 z-[200] hidden bg-black/85 backdrop-blur-md flex-col items-center justify-center text-center">
            <div class="w-24 h-24 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center relative overflow-hidden mb-8">
                <i data-lucide="scan-line" class="w-12 h-12 text-indigo-400"></i>
                <div class="absolute w-full h-0.5 bg-indigo-500 shadow-[0_0_10px_rgba(99,102,241,0.8)] animate-[scan-line_2s_linear_infinite]"></div>
            </div>
            <h2 class="text-3xl font-bold text-white mb-2 tracking-widest uppercase" style="font-family: 'Exo 2', sans-serif;">Scanning Link...</h2>
            <p class="text-indigo-300 font-mono text-sm max-w-sm animate-pulse" id="linkGuardStatus">Analyzing URL security...</p>
        </div>

        <!-- Link Guard Threat Alert -->
        <div id="linkGuardThreatModal" class="fixed inset-0 z-[210] hidden bg-black/90 backdrop-blur-xl flex items-center justify-center p-6">
            <div class="bg-[#1a0b14] border border-red-500/50 rounded-3xl max-w-lg w-full p-8 text-center relative shadow-[0_0_50px_rgba(220,38,38,0.3)]">
                <div class="w-20 h-20 bg-red-500/20 rounded-full flex items-center justify-center mx-auto mb-6 animate-bounce">
                    <i data-lucide="shield-alert" class="w-10 h-10 text-red-500"></i>
                </div>
                <h2 class="text-3xl font-bold text-red-500 mb-2 uppercase tracking-wide">⚠️ Unsafe Link Detected</h2>
                <p class="text-gray-300 mb-6 leading-relaxed">
                    SecureNet Shield has detected potential threats in this link. Proceeding may compromise your security.
                </p>
                
                <div class="bg-red-500/5 border border-red-500/20 rounded-xl p-4 mb-6 text-left">
                    <div class="flex items-center gap-3 mb-2">
                        <i data-lucide="link" class="w-5 h-5 text-red-400"></i>
                        <span class="text-red-400 font-bold text-sm uppercase">Target URL</span>
                    </div>
                    <p class="text-white text-xs font-mono break-all" id="linkGuardThreatUrl">-</p>
                </div>

                <div class="flex gap-4">
                    <button onclick="closeLinkGuardThreat()" class="flex-1 bg-gray-700 hover:bg-gray-600 text-white font-bold py-3 rounded-xl transition-all uppercase tracking-widest text-sm">
                        Go Back
                    </button>
                    <button onclick="proceedUnsafeLink()" class="flex-1 bg-red-600 hover:bg-red-700 text-white font-bold py-3 rounded-xl transition-all uppercase tracking-widest text-sm">
                        Proceed Anyway
                    </button>
                </div>
            </div>
        </div>

        <!-- Link Guard Safe Notification -->
        <div id="linkGuardSafeModal" class="fixed inset-0 z-[210] hidden bg-black/90 backdrop-blur-xl flex items-center justify-center p-6">
            <div class="bg-[#0b1a14] border border-green-500/50 rounded-3xl max-w-lg w-full p-8 text-center relative shadow-[0_0_50px_rgba(34,197,94,0.3)]">
                <div class="w-20 h-20 bg-green-500/20 rounded-full flex items-center justify-center mx-auto mb-6">
                    <i data-lucide="shield-check" class="w-10 h-10 text-green-500"></i>
                </div>
                <h2 class="text-3xl font-bold text-green-500 mb-2 uppercase tracking-wide">✓ Link Verified Safe</h2>
                <p class="text-gray-300 mb-6">
                    This link passed all security checks. Redirecting...
                </p>
                <div class="w-full bg-gray-800 rounded-full h-2 overflow-hidden">
                    <div class="bg-green-500 h-full animate-[progress_1s_ease-in-out]" style="width: 100%;"></div>
                </div>
            </div>
        </div>

        <style>
            @keyframes scan-line {
                0% { top: 0%; opacity: 0; }
                10% { opacity: 1; }
                90% { opacity: 1; }
                100% { top: 100%; opacity: 0; }
            }
            @keyframes progress {
                0% { width: 0%; }
                100% { width: 100%; }
            }
        </style>
    `;

    document.body.insertAdjacentHTML('beforeend', modalsHTML);

    // Re-initialize Lucide icons for modals
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }
}

// ========================================
// LINK GUARD: GLOBAL INTERCEPTOR
// ========================================
let pendingLinkUrl = null;

function initializeLinkGuard() {
    document.addEventListener('click', function (e) {
        const link = e.target.closest('a');

        // Ignore if not a link or if it's a same-page anchor
        if (!link || !link.href) return;

        const targetUrl = link.href;
        const currentDomain = window.location.hostname;
        const targetDomain = new URL(targetUrl).hostname;

        // Only intercept external links that don't have skip-scan enabled
        const skipScan = link.getAttribute('data-skip-scan') === 'true';

        if (!skipScan && targetDomain !== currentDomain && targetDomain !== '' && !targetUrl.startsWith('javascript:')) {
            e.preventDefault();
            pendingLinkUrl = targetUrl;
            scanLinkBeforeNavigation(targetUrl);
        }
    }, true); // Use capture phase to catch all clicks
}

async function scanLinkBeforeNavigation(url) {
    const overlay = document.getElementById('linkGuardScanOverlay');
    const status = document.getElementById('linkGuardStatus');

    // Show scanning overlay
    overlay.classList.remove('hidden');
    overlay.classList.add('flex');
    status.textContent = "Checking URL reputation...";

    // Simulate scanning steps
    setTimeout(() => { status.textContent = "Analyzing threat database..."; }, 300);
    setTimeout(() => { status.textContent = "Verifying SSL certificate..."; }, 600);

    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/api/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();
        const score = data.data.score;

        overlay.classList.add('hidden');
        overlay.classList.remove('flex');

        if (score <= 60) {
            // Show threat modal
            showLinkGuardThreat(url);
        } else {
            // Show safe modal and redirect
            showLinkGuardSafe(url);
        }
    } catch (err) {
        console.error('Link scan failed:', err);
        overlay.classList.add('hidden');
        overlay.classList.remove('flex');

        // On error, allow navigation with warning
        if (confirm('Unable to scan link. Proceed anyway?')) {
            window.open(url, '_blank');
        }
        pendingLinkUrl = null;
    }
}

function showLinkGuardThreat(url) {
    const modal = document.getElementById('linkGuardThreatModal');
    document.getElementById('linkGuardThreatUrl').textContent = url;
    modal.classList.remove('hidden');
}

function closeLinkGuardThreat() {
    document.getElementById('linkGuardThreatModal').classList.add('hidden');
    pendingLinkUrl = null;
}

function proceedUnsafeLink() {
    if (pendingLinkUrl) {
        window.open(pendingLinkUrl, '_blank');
    }
    closeLinkGuardThreat();
}

function showLinkGuardSafe(url) {
    const modal = document.getElementById('linkGuardSafeModal');
    modal.classList.remove('hidden');

    // Auto-redirect after 1.5 seconds
    setTimeout(() => {
        modal.classList.add('hidden');
        window.open(url, '_blank');
        pendingLinkUrl = null;
    }, 1500);
}

// Auto-load on script run
document.addEventListener('DOMContentLoaded', loadHeader);
