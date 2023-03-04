from fastapi import Request
import time
import jwt
import bcrypt
from typing import Dict
from dotenv import dotenv_values
from model import UserLoginSchema, UserSchema

config = dotenv_values()


JWT_SECRET = config["SECRET"]
JWT_ALGORITHM = config["ALGORITHM"]


def token_response(token: str):
    return {
        "access_token": token
    }

def signJWT(user_id: str) -> Dict[str, str]:
    payload = {
        "user_id": user_id,
        "expires": time.time() + 600
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    return token_response(token)

def decodeJWT(token: str) -> dict:
    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return decoded_token if decoded_token["expires"] >= time.time() else None
    except:
        return {}

def check_user(request: Request, user: UserLoginSchema):
    user_exists = request.app.database["users"].find_one(
        { "email": user.email }
    )
    if user is None:
        print("user not found")
        return False
    else:
        user_exists = UserSchema.parse_obj(user_exists)
        if bcrypt.checkpw(bytes(user.password, "utf-8"), bytes(user_exists.password, "utf-8")):
            return True
        else:
            return False