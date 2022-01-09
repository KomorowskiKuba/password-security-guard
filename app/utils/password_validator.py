import string


class PasswordValidator:
    @staticmethod
    def validate(password):
        not_satisfied = []

        if len(password) < 8:
            not_satisfied.append('Your password is too short! It should be at least 8 characters long!')

        if len(password) > 20:
            not_satisfied.append('Your password is too long! It should be maximum 20 characters long!')

        if not any(c.isupper() for c in password):
            not_satisfied.append('You password should contain at least one uppercase letter!')

        if not any(c.islower() for c in password):
            not_satisfied.append('You password should contain at least one lowercase letter!')

        if not any(c.isdigit() for c in password):
            not_satisfied.append('You password should contain at least one digit!')

        if not any(c in string.punctuation for c in password):
            not_satisfied.append('You password should contain at least one special character!')

        return not_satisfied
