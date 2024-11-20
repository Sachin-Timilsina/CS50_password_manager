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

// Navigate one step back in browser history
function goBack() {
    window.history.back();
}

// AJAX & JQuery to check password real-time 
$(document).ready(function () {
    // Event listener for password field
    $('#password').on('input', function () {
        var password = $(this).val();

        $.ajax({
            type: 'POST',
            url: '/check_password_strength',  // URL Flask endpoint
            contentType: 'application/json',
            data: JSON.stringify({
                password: password,
            }),
            success: function(response) { // On sucess display feedback
                let feedbackHtml = '';
                if (response.feedback) {
                    response.feedback.forEach(function (message) {
                        feedbackHtml += `<li class="text-danger">${message}</li>`;
                    });
                }
                if (response.feedback.length === 1 && response.feedback[0] === "Password is strong!") {
                    feedbackHtml = `<li class="text-success">Password is strong!</li>`;
                }

                $('#password-strength-messages').html(feedbackHtml);
            },
            error: function(error) {
                console.error('Error:', error);
            }
        });
    });
});

