// =========================
//  SCRIPT.JS - SECURENET
// =========================

const BASE_URL = CONFIG.API_BASE_URL;


// =========================
// TOAST POPUP (ONLY MESSAGE SYSTEM)
// =========================
function showToast(message, error = false) {
    const toast = document.getElementById("toast");
    if (!toast) return;

    toast.style.display = "block";
    toast.style.background = error
        ? "#2d1f1f"
        : "linear-gradient(90deg, #00f2ff, #008cff)";
    toast.style.color = error ? "#ff6b6b" : "#021024";

    toast.innerHTML = message;

    setTimeout(() => {
        toast.style.display = "none";
    }, 2500);
}


// =========================
// PASSWORD VISIBILITY (EYE)
// =========================
function togglePassword() {
    const pass = document.getElementById("password");
    if (!pass) return;

    pass.type = pass.type === "password" ? "text" : "password";
}


// =========================
// PASSWORD STRENGTH CHECK
// =========================
function checkPasswordStrength() {
    const password = document.getElementById("password").value;
    const strengthBox = document.getElementById("passwordStrength");

    if (!strengthBox) return;

    let strength = 0;

    if (password.length >= 8) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^A-Za-z0-9]/.test(password)) strength++;

    if (!password) {
        strengthBox.innerText = "Password strength: —";
        strengthBox.style.color = "#9fb4c8";
    } else if (strength <= 2) {
        strengthBox.innerText = "Password strength: Weak";
        strengthBox.style.color = "#ff6b6b";
    } else if (strength <= 4) {
        strengthBox.innerText = "Password strength: Medium";
        strengthBox.style.color = "#feca57";
    } else {
        strengthBox.innerText = "Password strength: Strong";
        strengthBox.style.color = "#1dd1a1";
    }
}


// =========================
// GENERATE STRONG PASSWORD
// =========================
function generateStrongPassword() {
    const chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$!%*?";
    let password = "";

    for (let i = 0; i < 12; i++) {
        password += chars.charAt(Math.floor(Math.random() * chars.length));
    }

    const passInput = document.getElementById("password");
    passInput.value = password;
    checkPasswordStrength();
}


// =========================
// SEND OTP (POPUP ONLY)
// =========================
async function sendOTP() {
    const email = document.getElementById("email").value.trim();

    if (!email) {
        showToast("⚠️ Please enter email first", true);
        return;
    }

    try {
        const response = await fetch(`${BASE_URL}/api/signup/send-otp`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email })
        });

        await response.json();

        // ✅ ONLY POPUP (NO INLINE MESSAGE)
        showToast("🔐 OTP sent successfully to your email");

        document.getElementById("otp").focus();

    } catch (error) {
        console.error(error);
        showToast("❌ Failed to send OTP. Try again.", true);
    }
}


// =========================
// REGISTER USER (POPUP ONLY)
// =========================
async function registerUser() {

    const requiredFields = [
        "firstName",
        "lastName",
        "contact",
        "email",
        "password",
        "dob",
        "gender",
        "otp"
    ];

    for (let id of requiredFields) {
        const el = document.getElementById(id);
        if (!el || !el.value.trim()) {
            showToast("⚠️ All fields are required", true);
            return;
        }
    }

    const payload = {
        first_name: firstName.value,
        last_name: lastName.value,
        contact: contact.value,
        email: email.value,
        password: password.value,
        dob: dob.value,
        gender: gender.value,
        otp: otp.value
    };

    try {
        const response = await fetch(`${BASE_URL}/api/signup`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        const data = await response.json();

        if (!data.success) {
            // ✅ ERROR POPUP ONLY
            showToast(`❌ ${data.message}`, true);
            return;
        }

        // ✅ SUCCESS POPUP ONLY
        showToast("✅ Signup successful! Redirecting to login…");

        setTimeout(() => {
            window.location.href = "login.html";
        }, 1800);

    } catch (error) {
        console.error(error);
        showToast("❌ Server error. Please try again.", true);
    }
}
// -----------------------------------------------------------
// ADMIN: LOAD USERS (JWT PROTECTED)
// -----------------------------------------------------------
async function loadAdminUsers() {
    const token = localStorage.getItem("token");

    if (!token) {
        window.location.href = "login.html";
        return;
    }

    const response = await fetch(`${BASE_URL}/api/admin/users`, {
        headers: {
            "Authorization": "Bearer " + token
        }
    });

    const data = await response.json();

    if (!data.success) {
        alert("Session expired. Please login again.");
        localStorage.removeItem("token");
        window.location.href = "login.html";
        return;
    }

    const tbody = document.getElementById("userTableBody");
    tbody.innerHTML = "";

    data.users.forEach(user => {
        const row = `
            <tr>
                <td>${user.id}</td>
                <td>${user.name}</td>
                <td>${user.email}</td>
                <td>${user.contact ?? "-"}</td>
                <td>${user.role}</td>
                <td>${user.status}</td>
                <td>
                    ${user.role === "admin"
                ? "—"
                : (user.status === "active"
                    ? `<button onclick="blockUser(${user.id})">Block</button>`
                    : `<button onclick="unblockUser(${user.id})">Unblock</button>`
                )
            }
                </td>
            </tr>
        `;
        tbody.innerHTML += row;
    });
}


// -----------------------------------------------------------
// BLOCK USER (JWT PROTECTED)
// -----------------------------------------------------------
async function blockUser(uid) {
    const token = localStorage.getItem("token");

    await fetch(`${BASE_URL}/api/admin/user/block/${uid}`, {
        method: "POST",
        headers: {
            "Authorization": "Bearer " + token
        }
    });

    loadAdminUsers();
}


// -----------------------------------------------------------
// UNBLOCK / ACTIVATE USER (JWT PROTECTED)
// -----------------------------------------------------------
async function unblockUser(uid) {
    const token = localStorage.getItem("token");

    await fetch(`${BASE_URL}/api/admin/user/activate/${uid}`, {
        method: "POST",
        headers: {
            "Authorization": "Bearer " + token
        }
    });

    loadAdminUsers();
}


// -----------------------------------------------------------
// SECURE LOGOUT
// -----------------------------------------------------------
function logout() {
    fetch(`${BASE_URL}/api/logout`, {
        method: "POST",
        headers: {
            "Authorization": "Bearer " + localStorage.getItem("token")
        }
    }).finally(() => {
        localStorage.clear();
        window.location.replace("login.html");
    });
}
// =========================
// FORGOT PASSWORD - SEND OTP
// =========================
async function forgotSendOTP() {
    const email = document.getElementById("fp_email").value.trim();

    if (!email) {
        showToast("⚠️ Please enter registered email", true);
        return;
    }

    try {
        await fetch(`${BASE_URL}/api/forgot/send-otp`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email })
        });

        showToast("🔐 OTP sent to your email");
        document.getElementById("fp_otp").focus();

    } catch (err) {
        showToast("❌ Failed to send OTP", true);
    }
}


// =========================
// RESET PASSWORD
// =========================
async function resetPassword() {
    const email = document.getElementById("fp_email").value.trim();
    const otp = document.getElementById("fp_otp").value.trim();
    const password = document.getElementById("fp_password").value.trim();

    if (!email || !otp || !password) {
        showToast("⚠️ All fields are required", true);
        return;
    }

    try {
        const res = await fetch(`${BASE_URL}/api/forgot/reset`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, otp, password })
        });

        const data = await res.json();

        if (!data.success) {
            showToast(`❌ ${data.message}`, true);
            return;
        }

        showToast("✅ Password updated successfully");

        setTimeout(() => {
            window.location.href = "login.html";
        }, 1800);

    } catch (err) {
        showToast("❌ Server error", true);
    }
}

