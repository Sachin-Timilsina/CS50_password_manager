// Toggle visibility of confirm password
function toggleConfirmPassword() {
    var confirmPasswordField = document.getElementById("confirm_password");
    var confirmEyeIcon = document.getElementById("confirm-eye-icon");
    if (confirmPasswordField.type === "password") {
        confirmPasswordField.type = "text";
        confirmEyeIcon.classList.remove("bi-eye");
        confirmEyeIcon.classList.add("bi-eye-slash");
    } else {
        confirmPasswordField.type = "password";
        confirmEyeIcon.classList.remove("bi-eye-slash");
        confirmEyeIcon.classList.add("bi-eye");
    }
}

// Toggle visibility of password
function togglePassword() {
    var passwordField = document.getElementById("password");
    var eyeIcon = document.getElementById("eye-icon");
    if (passwordField.type === "password") {
        passwordField.type = "text";
        eyeIcon.classList.remove("bi-eye");
        eyeIcon.classList.add("bi-eye-slash");
    } else {
        passwordField.type = "password";
        eyeIcon.classList.remove("bi-eye-slash");
        eyeIcon.classList.add("bi-eye");
    }
}
