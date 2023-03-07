from fastapi import Request
from loguru import logger
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
        return False
    else:
        user_exists = UserSchema.parse_obj(user_exists)
        if bcrypt.checkpw(bytes(user.password, "utf-8"), bytes(user_exists.password, "utf-8")):
            return True
        else:
            return False

def generate_password_link(user_id: str, password: str) -> str:
    payload = {
        "user_id": user_id,
        "expires": time.time() + 600
    }
    token = jwt.encode(payload, JWT_SECRET + password, algorithm=JWT_ALGORITHM)
    link = f"http://localhost:8000/user/reset/{ user_id }/{ token }"
    return link

def verify_payload_link(token: str, password: str) -> bool:
    try:
        decoded_token = jwt.decode(token, JWT_SECRET + password, algorithms=[JWT_ALGORITHM])
        if decoded_token["expires"] >= time.time():
            return True
        else:
            return False
    except Exception as err:
        return False