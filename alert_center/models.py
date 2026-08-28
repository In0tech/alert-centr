
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import secrets



from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()



class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(254), nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    _password_hash = db.Column("password", db.String(128), nullable=True)

    def set_unusable_password(self):
        self._password_hash = f"!unusable!{secrets.token_urlsafe(32)}"

    def has_usable_password(self):
        return not (self._password_hash is None or (isinstance(self._password_hash, str) and self._password_hash.startswith("!unusable!")))

    # opt
    #def set_password(self, plaintext, pwd_hasher):
    #    self._password_hash = pwd_hasher(plaintext)

    def check_password(self, plaintext, pwd_checker):
        if not self.has_usable_password():
            return False
        return pwd_checker(self._password_hash, plaintext)
