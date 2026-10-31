/* LLM Wiki sign-in page. Credentials are checked against VSDA Deep Agent. */
(function () {
    'use strict';

    var THEME_KEY = 'llm-wiki-login-theme';
    var root = document.documentElement;

    var MESSAGES = {
        INVALID_CREDENTIALS: 'Incorrect username or password. Use your VSDA Deep Agent account.',
        TOO_MANY_ATTEMPTS: 'Too many sign-in attempts. Wait a minute, then try again.',
        SERVICE_UNAVAILABLE: 'VSDA Deep Agent cannot be reached right now. Try again in a moment.',
        SIGNED_OUT: 'You have been signed out.',
        NETWORK: 'Could not reach the sign-in service. Check your connection and try again.',
        INSECURE: 'This connection is not secure. Sign-in is disabled. Open this page over HTTPS.'
    };

    function $(id) {
        return document.getElementById(id);
    }

    function readCookie(name) {
        var parts = document.cookie ? document.cookie.split(';') : [];
        for (var i = 0; i < parts.length; i++) {
            var pair = parts[i].trim();
            if (pair.indexOf(name + '=') === 0) {
                try {
                    return decodeURIComponent(pair.slice(name.length + 1));
                } catch (e) {
                    return pair.slice(name.length + 1);
                }
            }
        }
        return null;
    }

    function clearCookie(name) {
        document.cookie = name + '=; Max-Age=0; Path=/login; SameSite=Lax';
        document.cookie = name + '=; Max-Age=0; Path=/login/; SameSite=Lax';
    }

    /* ---------------------------------------------------------- theme */

    var themeToggle = $('themeToggle');

    function applyTheme(theme) {
        if (root.dataset.theme && root.dataset.theme !== theme) {
            // Suppress color transitions for the switch so the page recolors in one frame.
            root.setAttribute('data-theme-switching', '');
            window.requestAnimationFrame(function () {
                window.requestAnimationFrame(function () {
                    root.removeAttribute('data-theme-switching');
                });
            });
        }
        root.dataset.theme = theme;
        if (themeToggle) {
            themeToggle.setAttribute('aria-label', theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
        }
    }

    function savedTheme() {
        try {
            var value = localStorage.getItem(THEME_KEY);
            return value === 'dark' || value === 'light' ? value : null;
        } catch (e) {
            return null;
        }
    }

    var prefersDark = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;
    applyTheme(savedTheme() || (prefersDark && prefersDark.matches ? 'dark' : 'light'));

    // The container's DARK_MODE setting wins over the OS preference unless the user chose a theme here.
    fetch('webdata.json', { cache: 'no-store' })
        .then(function (response) { return response.ok ? response.json() : null; })
        .then(function (data) {
            if (data && data.darkMode && !savedTheme()) {
                applyTheme('dark');
            }
        })
        .catch(function () { /* optional */ });

    if (prefersDark && prefersDark.addEventListener) {
        prefersDark.addEventListener('change', function (event) {
            if (!savedTheme()) {
                applyTheme(event.matches ? 'dark' : 'light');
            }
        });
    }

    if (themeToggle) {
        themeToggle.addEventListener('click', function () {
            var next = root.dataset.theme === 'dark' ? 'light' : 'dark';
            applyTheme(next);
            try {
                localStorage.setItem(THEME_KEY, next);
            } catch (e) { /* storage unavailable */ }
        });
    }

    /* --------------------------------------------------------- footer */

    var year = $('copyrightYear');
    if (year) {
        year.textContent = new Date().getFullYear() + ' ';
    }

    /* ----------------------------------------------------------- form */

    // Same-origin paths only: "//host" and "/\host" are protocol-relative.
    function safeRedirect(target) {
        return typeof target === 'string' && /^\/(?![\/\\])/.test(target) ? target : '/';
    }

    var form = $('loginForm');
    var fieldset = $('loginFieldset');
    var username = $('usernameInput');
    var password = $('passwordInput');
    var usernameError = $('usernameError');
    var passwordError = $('passwordError');
    var button = $('loginButton');
    var buttonLabel = $('loginButtonLabel');
    var status = $('loginStatus');
    var statusText = $('loginStatusText');
    var passwordToggle = $('passwordToggle');

    function showStatus(kind, message) {
        status.classList.remove('status--error', 'status--info');
        status.classList.add(kind === 'info' ? 'status--info' : 'status--error');
        statusText.textContent = message;
        status.hidden = false;
    }

    function hideStatus() {
        status.hidden = true;
        statusText.textContent = '';
    }

    function setBusy(busy) {
        button.disabled = busy;
        button.setAttribute('aria-busy', busy ? 'true' : 'false');
        buttonLabel.textContent = busy ? 'Signing in\u2026' : 'Sign in';
    }

    function setFieldError(input, errorEl, invalid) {
        errorEl.hidden = !invalid;
        if (invalid) {
            input.setAttribute('aria-invalid', 'true');
        } else {
            input.removeAttribute('aria-invalid');
        }
    }

    function validate() {
        var userMissing = username.value.trim() === '';
        var passMissing = password.value === '';
        setFieldError(username, usernameError, userMissing);
        setFieldError(password, passwordError, passMissing);
        if (userMissing) {
            username.focus();
        } else if (passMissing) {
            password.focus();
        }
        return !userMissing && !passMissing;
    }

    username.addEventListener('input', function () {
        if (username.value.trim() !== '') {
            setFieldError(username, usernameError, false);
        }
    });
    password.addEventListener('input', function () {
        if (password.value !== '') {
            setFieldError(password, passwordError, false);
        }
    });

    passwordToggle.addEventListener('click', function () {
        var show = password.type === 'password';
        password.type = show ? 'text' : 'password';
        passwordToggle.setAttribute('aria-pressed', show ? 'true' : 'false');
        passwordToggle.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
        password.focus();
    });

    // Browsers only expose credentials safely over HTTPS (or on localhost).
    var secureContext = window.isSecureContext === true;
    if (!secureContext) {
        fieldset.disabled = true;
        showStatus('error', MESSAGES.INSECURE);
    } else {
        var result = readCookie('login_result');
        if (result && MESSAGES[result]) {
            showStatus(result === 'SIGNED_OUT' ? 'info' : 'error', MESSAGES[result]);
        }
    }
    clearCookie('login_result');

    if (secureContext && !username.value) {
        username.focus();
    }

    form.addEventListener('submit', function (event) {
        event.preventDefault();
        if (!secureContext || button.disabled) {
            return;
        }
        hideStatus();
        if (!validate()) {
            return;
        }

        setBusy(true);
        var body = new URLSearchParams();
        body.set('username', username.value.trim());
        body.set('password', password.value);

        fetch(form.getAttribute('action'), {
            method: 'POST',
            credentials: 'same-origin',
            cache: 'no-store',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
            },
            body: body.toString()
        })
            .then(function (response) {
                return response.json().catch(function () { return null; }).then(function (data) {
                    return { response: response, data: data };
                });
            })
            .then(function (outcome) {
                var data = outcome.data || {};
                if (outcome.response.ok && data.ok) {
                    buttonLabel.textContent = 'Opening LLM Wiki\u2026';
                    window.location.replace(safeRedirect(data.redirect));
                    return;
                }
                setBusy(false);
                var code = data.error && MESSAGES[data.error] ? data.error
                    : outcome.response.status === 429 ? 'TOO_MANY_ATTEMPTS'
                    : outcome.response.status === 401 ? 'INVALID_CREDENTIALS'
                    : 'SERVICE_UNAVAILABLE';
                showStatus('error', MESSAGES[code]);
                if (code === 'INVALID_CREDENTIALS') {
                    password.value = '';
                    password.focus();
                }
            })
            .catch(function () {
                setBusy(false);
                showStatus('error', MESSAGES.NETWORK);
            });
    });
})();
