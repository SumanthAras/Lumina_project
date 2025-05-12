const loginSec = document.querySelector('.login-section');
const loginLink = document.querySelector('.login-link');
const registerLink = document.querySelector('.register-link');
const loginForm = document.querySelector('.form-box.login form');
const registerForm = document.querySelector('.form-box.register form');

// Function to clear form inputs
function clearForm(form) {
    form.reset(); // Resets all input fields inside the form
}

// Register Link Click - Switch to Register Form & Clear Fields
registerLink.addEventListener('click', () => {
    loginSec.classList.add('active');
    clearForm(loginForm);  // Clears login form when switching to register
});

// Login Link Click - Switch to Login Form & Clear Fields
loginLink.addEventListener('click', () => {
    loginSec.classList.remove('active');
    clearForm(registerForm);  // Clears register form when switching to login
});

// Ensure forms are cleared on page load
window.addEventListener('load', () => {
    clearForm(loginForm);
    clearForm(registerForm);
});
