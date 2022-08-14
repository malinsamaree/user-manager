import express from "express";
import {register, login, logoff, refresh, verify} from "../controllers/user.controllers";

const router = express.Router();

router.get('/', (req, res, next) => {
    res.send('from user home page')
});

router.post('/register', register);

router.post("/login", login);

router.post('/logoff', logoff);

router.get("/verify", verify);

router.get("/refresh", refresh);

export {router}

