(function () {
    const token = localStorage.getItem("token");
    const role = localStorage.getItem("role");

    function checkAdmin() {
        if (!token || !role || role !== "admin") {
            if (window.stop) window.stop();
            localStorage.clear();
            window.location.replace("login.html");
            return false;
        }
        return true;
    }

    // 1. Run Admin Check Immediately
    if (!checkAdmin()) return;

    // 2. If Admin Passed, Show Content When Ready
    window.addEventListener('DOMContentLoaded', () => {
        document.body.style.display = 'block';
    });

    // 3. Continuous Protection
    window.addEventListener("pageshow", function () {
        const currentToken = localStorage.getItem("token");
        const currentRole = localStorage.getItem("role");

        if (!currentToken || currentRole !== "admin") {
            document.body.style.display = 'none';
            window.location.replace("login.html");
        }
    });
})();
