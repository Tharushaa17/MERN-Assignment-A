import express from 'express';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import cors from 'cors';
import authRoutes from './src/routes/auth.routes.js';
import cookieParser from 'cookie-parser';
import userRoutes from './src/routes/user.routes.js';
import { corsOptions } from './src/utils/corsOptions.js';
dotenv.config();
const app = express();

// Middelware
app.use(express.json());
app.use(cors());
app.use(cookieParser());

// routes
app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes);

// Error Handing Middelware
app.use((err, req, res, next) => {
const statusCode = err.statusCode || 500;
const message = err.message || 'Internal Server Error';
    return res.status(statusCode).json({
        success: false,
        statusCode,
        message,
    });
});

const port =  5000;

const start = async () =>{
    try {
        await mongoose.connect(process.env.MONGO_URL)
        app.listen(port, console.log(`Server is Listing to port : ${port} & DB Connected!`));
    } catch (error) {
        console.log(error);
    }
}

start()