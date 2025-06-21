window.Auth = (function() {
    const TOKEN_KEY = 'dr4ke_auth_token';
    const CSRF_KEY = 'dr4ke_csrf_token';
    
    console.log('[DEBUG] Auth module loaded');

    function getToken() {
        const token = localStorage.getItem(TOKEN_KEY);
        console.log('[DEBUG] getToken:', { hasToken: !!token, token: token });
        return token;
    }

    function getCSRFToken() {
        const csrf = localStorage.getItem(CSRF_KEY);
        console.log('[DEBUG] getCSRFToken:', { hasCsrf: !!csrf, csrf: csrf });
        return csrf;
    }

    async function saveTokens(token, csrf) {
        console.log('[DEBUG] Saving tokens:', { token, csrf });
        if (!token || !csrf) {
            console.error('[DEBUG] Missing token or csrf');
            return;
        }

        try {
            localStorage.setItem(TOKEN_KEY, token);
            localStorage.setItem(CSRF_KEY, csrf);
            console.log('[DEBUG] Tokens saved successfully');

            await fetch('/auth/save-token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token }),
                credentials: 'include'
            });
        } catch (err) {
            console.error('[DEBUG] Error saving tokens:', err);
            throw err;
        }
    }

    function clearTokens() {
        console.log('[DEBUG] Clearing tokens');
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(CSRF_KEY);
    }

    async function verifyAuth() {
        console.log('[DEBUG] Verifying authentication');
        try {
            const csrf = getCSRFToken();
            if (!csrf) {
                console.log('[DEBUG] No CSRF token found');
                return false;
            }

            const response = await fetch('/auth/verify', {
                headers: {
                    'X-CSRF-Token': csrf
                },
                credentials: 'include'
            });

            console.log('[DEBUG] Verify response:', { 
                status: response.status,
                headers: Object.fromEntries([...response.headers.entries()])
            });

            if (!response.ok) {
                console.error('[DEBUG] Verify request failed:', response.status);
                return false;
            }

            const data = await response.json();
            console.log('[DEBUG] Verify result:', data);
            return data.valid === true;
        } catch (err) {
            console.error('[DEBUG] Verify error:', err);
            return false;
        }
    }

    async function login(username, password) {
        console.log('[DEBUG] Attempting login:', { username });
        try {
            console.log('[DEBUG] Making login request to /auth/login');
            const response = await fetch('/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password }),
                credentials: 'include'
            });

            console.log('[DEBUG] Login response status:', response.status);
            console.log('[DEBUG] Login response headers:', Object.fromEntries([...response.headers.entries()]));

            if (!response.ok) {
                console.error('[DEBUG] Login response not OK:', response.status, response.statusText);
                return false;
            }

            const data = await response.json();
            console.log('[DEBUG] Login response data:', data);

            if (data.success && data.token && data.csrf) {
                console.log('[DEBUG] Login successful, saving tokens');
                await saveTokens(data.token, data.csrf);
                
                console.log('[DEBUG] Verifying authentication before redirect');
                const isValid = await verifyAuth();
                if (!isValid) {
                    console.error('[DEBUG] Auth verification failed after login');
                    return false;
                }

                console.log('[DEBUG] Redirecting to dashboard...');
                window.location.href = '/html/dashboard.html';
                return true;
            }
            console.error('[DEBUG] Login failed:', data);
            return false;
        } catch (err) {
            console.error('[DEBUG] Login error:', err);
            return false;
        }
    }

    async function logout() {
        console.log('[DEBUG] Logging out');
        try {
            const csrf = getCSRFToken();
            if (csrf) {
                const response = await fetch('/auth/logout', {
                    method: 'GET',
                    headers: { 'X-CSRF-Token': csrf },
                    credentials: 'include'
                });
                console.log('[DEBUG] Logout response:', { 
                    status: response.status,
                    headers: Object.fromEntries([...response.headers.entries()])
                });
            }
        } catch (err) {
            console.error('[DEBUG] Logout error:', err);
        } finally {
            clearTokens();
            window.location.href = '/';
        }
    }

    return {
        getToken,
        getCSRFToken,
        login,
        logout,
        verifyAuth,
        isAuthenticated: () => !!getToken() && !!getCSRFToken()
    };
})();