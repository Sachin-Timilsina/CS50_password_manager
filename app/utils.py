from password_strength import PasswordStats

def check_password_strength(password):
    stats = PasswordStats(password)

    strength_score = stats.strength()
    feedback = []

    if len(password) < 8:
        feedback.append("Password should be at least 8 characters")
    if not any(char.isdigit() for char in password):
        feedback.append("Password should contain at least 1 digit.")
    if not any(char.isupper() for char in password):
        feedback.append("Password should contain at least 1 upper cased character.")
    if not any(char.islower() for char in password):
        feedback.append("Password should contain at least 1 lower cased character.")
    if not any(char in "!@#$%^&*(){}[]|\/.;''?+=-`,><:" for char in password):
        feedback.append("Password should contain at least one special character.")

    if feedback:
        return {"strength_score": strength_score, "feedback": feedback}
    else:
        return {"strength_score": strength_score, "feedback": ["Password is strong!"]} 