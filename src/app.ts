import express, {ErrorRequestHandler} from 'express';
import {Server} from 'http';
import cors from 'cors';
import createError from "http-errors";
import mongoose from "mongoose";
import jwt from 'jsonwebtoken';
import {config} from 'dotenv';
config();

import {router} from "./routes/user.routes";

mongoose.connect('mongodb+srv://malinsamare:swordfish2911@cluster0.1rw7o.mongodb.net/user-manager?retryWrites=true&w=majority')
    .then(() => {console.log('mongodb connected')})
    .catch(() => {
        // has to manage this error by giving a proper feedback to the customer (may be server error)
        console.log('mongodb connection error')}
    );

const app = express();
app.use(express.json());
app.use(cors());
app.use('/user', router);

app.use((req, res, next) => {
    next(new createError.NotFound());
});

const errorRequestHandler: ErrorRequestHandler = (err, req, res, next) => {
    res.send({
        "error": true,
        "message": err.message,
        "status": err.status
    });
}

app.use(errorRequestHandler);

const port  = process.env.PORT || 8080;
const server: Server =  app.listen(port, () => {
    console.log(`app is listening at port ${port}`)
});