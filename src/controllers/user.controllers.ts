import {RequestHandler} from 'express';
import createError from "http-errors";
import validator from "validator";
import {User} from "../models/user.model";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import {RefreshToken} from "../models/refreshToken.model";
import mongoose from "mongoose";

const register: RequestHandler = async (req, res, next) => {
    try {
        const email = req.body.email;
        const password = req.body.password;
        if(!email || !password) throw new createError.BadRequest('email or password or both are missing');
        if (!validator.isEmail(email)) throw new createError.BadRequest('invalid email');
        const isValidPassword = validator.isStrongPassword(password, {
            minLength: 8,
            minLowercase: 1,
            minUppercase: 1,
            minNumbers: 1,
            minSymbols: 1
        });
        if (!isValidPassword) throw new createError.BadRequest('password is not strong enough');

        const normalizedEmail = validator.normalizeEmail(email, {all_lowercase: true});

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const existingUser = await User.findOne({email: normalizedEmail});

        if(existingUser) throw new createError.Conflict('this email is already registered');

        const user = new User({email: normalizedEmail, password: hashedPassword});
        const savedUser = await user.save();

        res.send(savedUser);
    } catch (e) {
        next(e)
    }
};

const createTokens = (userId: mongoose.Types.ObjectId) => {
    const accessToken = jwt.sign({id: userId}, 'access_token_secret', {expiresIn: 3600});
    const refreshToken = jwt.sign({id: userId}, 'refresh_token_secret', {expiresIn: 60*60*24*30});

    if (!accessToken || !refreshToken) throw new createError.InternalServerError();

    return {accessToken, refreshToken};
}

const login: RequestHandler = async (req, res, next) => {
    try {
        const email = req.body.email;
        const password = req.body.password;
        if(!email || !password) throw new createError.BadRequest('email or password or both are missing');
        if (!validator.isEmail(email)) throw new createError.BadRequest('invalid email');
        const normalizedEmail = validator.normalizeEmail(email, {all_lowercase: true});
        const existingUser = await User.findOne({email: normalizedEmail});
        if (!existingUser) throw new createError.NotFound('user not found');
        const isPasswordValid = existingUser.password && await bcrypt.compare(password, existingUser.password);
        if (!isPasswordValid) throw new createError.Unauthorized('email or password not correct');

        const {accessToken, refreshToken} = createTokens(existingUser._id);

        const savedRefreshToken = await RefreshToken.findOneAndUpdate(
            {userId: existingUser._id},
            {userId: existingUser._id, refreshToken},
            {upsert: true, new: true},
        );

        if(!savedRefreshToken) throw new createError.InternalServerError();

        res.send({accessToken, refreshToken});
    } catch (e) {
        next(e)
    }
};

const logoff: RequestHandler = async (req, res, next) => {
    try {
        const refreshToken = req.body.refreshToken;
        const payload = jwt.verify(refreshToken, 'refresh_token_secret');
        const id = (<{id: string}>payload).id;
        const deletedRefreshToken = await RefreshToken.deleteOne({userId: id, refreshToken: refreshToken});
        // if deletecount is 0, should log to sentry
        res.send({deleted: deletedRefreshToken.acknowledged});
    } catch (e) {
        next(e);
    }
}

const refresh: RequestHandler = async (req, res, next) => {
    try {
        const refreshTokenHeader = req.headers.authorization?.split(" ")[1];
        const payload = refreshTokenHeader && jwt.verify(refreshTokenHeader, 'refresh_token_secret');
        const id = (<{id: string}>payload).id;
        const existingUser = await RefreshToken.findOne({userId: id, refreshToken: refreshTokenHeader});
        if(!existingUser) throw new createError.Unauthorized();

        const accessToken = jwt.sign({id: id}, 'access_token_secret', {expiresIn: 3600});
        const refreshToken = jwt.sign({id: id}, 'refresh_token_secret', {expiresIn: 60*60*24*30});

        if (!accessToken || !refreshToken) throw new createError.InternalServerError();

        const savedRefreshToken = await RefreshToken.findOneAndUpdate(
            {userId: id},
            {userId: id, refreshToken}
        );

        console.log(savedRefreshToken);

        if(!savedRefreshToken) throw new createError.InternalServerError('is2');

        res.send({accessToken, refreshToken});
    }catch {
        next(new createError.Unauthorized('invalid refresh token'));
    }
};

const verify:RequestHandler = async (req, res, next) => {
    try {
        const accessToken = req.headers.authorization?.split(" ")[1];
        const payload = accessToken && jwt.verify(accessToken, 'access_token_secret');
        const id = (<{id: string}>payload).id;
        res.send({"userId": id});
    }catch {
        next(new createError.Unauthorized('invalid access token'));
    }
};

export {register, login, logoff, refresh, verify};