// Local threat intelligence data (Mock Blacklist)
const blacklist = [
    "secure-paypal-login.com",
    "netflix-verify-account.xyz",
    "free-robux-claim.net",
    "facebook-security-update.click",
    "chase-online-banking.top"
];

// Global page body helper function to swap background states
function updateGlobalBackground(state) {
    const body = document.getElementById("pageBody");
    // Clear old state configurations
    body.classList.remove("bg-safe", "bg-warning", "bg-danger");
    
    if (state === "safe") body.classList.add("bg-safe");
    if (state === "warning") body.classList.add("bg-warning");
    if (state === "danger") body.classList.add("bg-danger");
}

// Tab Switching Mechanism
function switchTab(tabId) {
    document.querySelectorAll('.tab-content').forEach(content => content.classList.add('hidden'));
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    
    // Clear fields and reset background when changing sections
    updateGlobalBackground("default");
    document.getElementById("urlInput").value = "";
    document.getElementById("pwdInput").value = "";
    document.getElementById("resultCard").classList.add("hidden");
    document.getElementById("pwdResultCard").classList.add("hidden");

    document.getElementById(tabId).classList.remove('hidden');
    if(tabId === 'url-scanner') document.getElementById('urlTabBtn').classList.add('active');
    if(tabId === 'pwd-checker') document.getElementById('pwdTabBtn').classList.add('active');
}

// 🌐 Tool 1: URL Scanner
function scanURL() {
    const urlInput = document.getElementById("urlInput").value.trim().toLowerCase();
    const resultCard = document.getElementById("resultCard");
    const riskLevel = document.getElementById("riskLevel");
    const reasonList = document.getElementById("reasonList");

    reasonList.innerHTML = "";
    resultCard.className = "result-card"; 

    if (!urlInput) {
        alert("Please enter a URL to scan.");
        return;
    }

    let score = 0;
    let reasons = [];

    for (let badDomain of blacklist) {
        if (urlInput.includes(badDomain)) {
            score += 3;
            reasons.push(`Matches blacklisted threat database entry: '${badDomain}'`);
            break;
        }
    }

    const suspiciousKeywords = ["login", "verify", "bank", "secure", "update", "paypal", "netflix", "signin"];
    let foundKeywords = suspiciousKeywords.filter(word => urlInput.includes(word));
    if (foundKeywords.length > 0) {
        score += 1;
        reasons.push(`Contains deceptive keyword(s): ${foundKeywords.join(", ")}`);
    }

    const suspiciousTlds = [".xyz", ".top", ".click", ".win", ".club"];
    for (let tld of suspiciousTlds) {
        if (urlInput.endsWith(tld) || urlInput.includes(`${tld}/`)) {
            score += 1;
            reasons.push(`Uses a high-risk Top-Level Domain (TLD): '${tld}'`);
            break;
        }
    }

    if (score >= 3) {
        riskLevel.innerText = "🚨 HIGH RISK";
        resultCard.classList.add("high-risk");
        updateGlobalBackground("danger"); // Changes page to dark red
    } else if (score === 1 || score === 2) {
        riskLevel.innerText = "⚠️ MEDIUM RISK";
        resultCard.classList.add("medium-risk");
        updateGlobalBackground("warning"); // Changes page to orange/amber
    } else {
        riskLevel.innerText = "✅ LOW RISK";
        resultCard.classList.add("low-risk");
        updateGlobalBackground("safe"); // Changes page to green
    }

    if (reasons.length > 0) {
        reasons.forEach(reason => {
            let li = document.createElement("li");
            li.innerText = reason;
            reasonList.appendChild(li);
        });
    } else {
        let li = document.createElement("li");
        li.innerText = "No obvious phishing indicators or malicious signatures detected.";
        reasonList.appendChild(li);
    }

    resultCard.classList.remove("hidden");
}

// 🔑 Tool 2: Password Strength Checker
function checkPassword() {
    const password = document.getElementById("pwdInput").value;
    const pwdResultCard = document.getElementById("pwdResultCard");
    const pwdStrength = document.getElementById("pwdStrength");
    const strengthBar = document.getElementById("strengthBar");
    const feedbackList = document.getElementById("pwdFeedbackList");

    feedbackList.innerHTML = "";
    pwdResultCard.className = "result-card";

    if (!password) {
        pwdResultCard.classList.add("hidden");
        updateGlobalBackground("default"); // Returns back to clear blue if input is deleted
        return;
    }

    let score = 0;
    let feedback = [];

    if (password.length >= 8) score++;
    else feedback.push("Password should be at least 8 characters long.");

    if (/[A-Z]/.test(password)) score++;
    else feedback.push("Add at least one uppercase letter (A-Z).");

    if (/[0-9]/.test(password)) score++;
    else feedback.push("Add at least one number (0-9).");

    if (/[^A-Za-z0-9]/.test(password)) score++;
    else feedback.push("Add at least one special character (e.g., !, @, #, $).");

    if (score <= 2) {
        pwdStrength.innerText = "❌ WEAK PASSWORD";
        pwdResultCard.classList.add("strength-weak");
        strengthBar.style.width = "33%";
        strengthBar.style.backgroundColor = "#ef4444";
        updateGlobalBackground("danger"); // Changes page to dark red
    } else if (score === 3) {
        pwdStrength.innerText = "⚠️ MEDIUM PASSWORD";
        pwdResultCard.classList.add("strength-medium");
        strengthBar.style.width = "66%";
        strengthBar.style.backgroundColor = "#eab308";
        updateGlobalBackground("warning"); // Changes page to orange/amber
    } else if (score === 4) {
        pwdStrength.innerText = "✅ STRONG PASSWORD";
        pwdResultCard.classList.add("strength-strong");
        strengthBar.style.width = "100%";
        strengthBar.style.backgroundColor = "#22c55e";
        updateGlobalBackground("safe"); // Changes page to green
    }

    if (feedback.length > 0) {
        feedback.forEach(tip => {
            let li = document.createElement("li");
            li.innerText = tip;
            feedbackList.appendChild(li);
        });
    } else {
        let li = document.createElement("li");
        li.innerText = "Excellent! Your password meets all security metrics.";
        feedbackList.appendChild(li);
    }

    pwdResultCard.classList.remove("hidden");
}