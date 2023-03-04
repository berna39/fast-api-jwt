from fastapi import FastAPI, Body, Depends, Request, Response
from model import PostSchema, UserSchema, UserLoginSchema
from fastapi.encoders import jsonable_encoder
from typing import List
from pymongo import MongoClient
from dotenv import dotenv_values
import bcrypt

from auth.auth_handler import signJWT, check_user
from auth.auth_bearer import JWTBearer

app = FastAPI()
config = dotenv_values()

@app.on_event("startup")
def statup():
    app.mongo_client = MongoClient(config["MONGO_URL"])
    app.database = app.mongo_client[config["MONGO_DB"]]

@app.on_event("shutdown")
def shutdown():
    app.mongo_client.close()

users = []


@app.get("/")
async def root() -> dict:
    return {"message": "Hello from the app"}

@app.get("/posts", dependencies=[Depends(JWTBearer())], tags=["posts"], response_model=List[PostSchema])
async def get_posts(request: Request):
    posts = list(request.app.database["posts"].find(limit=100))
    return posts 


@app.get("/posts/{id}", tags=["posts"])
async def get_single_post(id: int) -> dict:
    pass

@app.post("/posts", tags=["posts"], response_model=PostSchema)
async def add_post(post: PostSchema, request: Request):
    post = jsonable_encoder(post)
    new_post = request.app.database["posts"].insert_one(post)
    created_post = request.app.database["posts"].find_one(
        { "_id": new_post.inserted_id }
    )

    return created_post


@app.post("/user/signup", tags=["user"])
async def create_user(request: Request, user: UserSchema = Body(...)):
    user.password = bcrypt.hashpw(bytes(user.password, "utf-8"), bcrypt.gensalt())
    user = jsonable_encoder(user)
    new_user = request.app.database["users"].insert_one(user)
    created_user = request.app.database["users"].find_one(
        { "_id": new_user.inserted_id }
    )
    created_user = UserSchema.parse_obj(created_user)

    return signJWT(created_user.id)

@app.post("/user/login", tags=["user"])
async def user_login(request: Request, user: UserLoginSchema = Body(...)):
    if check_user(request, user):
        user = request.app.database["users"].find_one({ "email": user.email })
        user = UserSchema.parse_obj(user)
        return signJWT(user.id)
    return {
        "error": "Wrong login details!"
    }
