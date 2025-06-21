document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    const loginError = document.getElementById('login-error');
    const loginBtn = document.getElementById('login-btn');

    console.log('[DEBUG] Login form elements:', {
        form: !!loginForm,
        error: !!loginError,
        button: !!loginBtn
    });

    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            console.log('[DEBUG] Login form submitted');
            
            if (loginBtn) {
                loginBtn.disabled = true;
                loginBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Logging in...';
            }
            
            if (loginError) {
                loginError.classList.add('hidden');
            }

            const username = document.getElementById('username')?.value;
            const password = document.getElementById('password')?.value;

            console.log('[DEBUG] Login attempt with username:', username);

            try {
                if (!window.Auth) {
                    console.error('[DEBUG] Auth module not found!');
                    throw new Error('Authentication module not loaded');
                }
                console.log('[DEBUG] Calling Auth.login...');
                const success = await window.Auth.login(username, password);
                console.log('[DEBUG] Login result:', success);
                
                if (!success) {
                    console.log('[DEBUG] Login failed, showing error');
                    if (loginError) {
                        loginError.classList.remove('hidden');
                        loginError.textContent = 'Invalid username or password. Please try again.';
                    }
                    
                    if (loginBtn) {
                        loginBtn.disabled = false;
                        loginBtn.innerHTML = '<i class="fas fa-sign-in-alt mr-2"></i>Secure Login';
                    }
                }
            } catch (error) {
                console.error('[DEBUG] Login error:', error);
                if (loginError) {
                    loginError.classList.remove('hidden');
                    loginError.textContent = 'An error occurred during login. Please try again.';
                }

                if (loginBtn) {
                    loginBtn.disabled = false;
                    loginBtn.innerHTML = '<i class="fas fa-sign-in-alt mr-2"></i>Secure Login';
                }
            }
        });
    } else {
        console.error('[DEBUG] Login form not found in the document!');
    }
}); 