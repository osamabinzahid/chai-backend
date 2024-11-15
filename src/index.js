//require('dotenv').config({path: './env'})
import dotenv from "dotenv"

//import express from "express";
//import { error } from "console";
import connectDB from "./db/index.js";

dotenv.config({
    path: './env'
})

connectDB()


/*
const app = express()

(async () => {
    try {
       await mongoose.connect(`${process.env.MONGODB_URI}/${DB_NAME}` )
       app.on("errror", () => {
        console.log("ERRR", error);
        throw error
       })

       app.listen(process.env.PORT, () => {
        console.log(`App is listening on port ${process.env.PORT}`);
       })

    } catch (error) {
        console.error("ERROR:", error)
        throw err
    }
})() */