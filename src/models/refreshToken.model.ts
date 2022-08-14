import mongoose from "mongoose";

const refreshTokenSchema = new mongoose.Schema({
    userId: {
        type: String,
        required: true,
        unique: true
    },
    refreshToken: {
        type: String,
        required: true
    }
});

const RefreshToken = mongoose.model('refreshToken', refreshTokenSchema);

export {RefreshToken};