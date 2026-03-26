(function () {
    const token = localStorage.getItem("token");

    function checkAuth() {
        if (!token || token === "null" || token === "undefined") {
            if (window.stop) window.stop();
            localStorage.clear();
            window.location.replace("login.html");
            return false;
        }
        return true;
    }

    // 1. Run Auth Check Immediately
    if (!checkAuth()) return;

    // 2. If Auth Passed, Show Content When Ready
    // We expect body to be hidden by default: <body style="display:none">
    window.addEventListener('DOMContentLoaded', () => {
        document.body.style.display = 'block';
    });

    // 3. Continuous Protection (Back Button)
    window.addEventListener("pageshow", function (event) {
        // Re-check on every view
        const currentToken = localStorage.getItem("token");
        if (!currentToken || currentToken === "null" || currentToken === "undefined") {
            document.body.style.display = 'none'; // Hide immediately
            window.location.replace("login.html");
        }
    });
})();
