import dotenv from "dotenv";
import connectDB from "./db/index.js";
import { app } from "./app.js";

dotenv.config({
  path: `./.env`,
});

connectDB()
  .then(() => {
    app.on("error", (error) => {
      console.error("MongoDB connection error", error);
    })
    app.listen(process.env.PORT || 8000, () => {
      console.log(`Server is running at port ${process.env.PORT}`);
    })
  })
  .catch((error) => {
    console.error("MongoDB connection failed", error);
    process.exit(1);
  })

/*
import mongoose from "mongoose";
import { DB_NAME } from "../constants";

import express from "express";
const app = express();

(async () => {
  try {
    console.log(process.env.MONGODB_URI)
    await mongoose.connect(`${process.env.MONGODB_URI}/${DB_NAME}`);
    app.on("error", (error) => {
      console.error("MongoDB connection error", error);
    });
    app.listen(process.env.PORT, () => {
      console.log(`App listening on port ${process.env.PORT}`);
    });
  } catch (error) {
    console.error("Failed to connect to MongoDB", error);
    throw error;
  }
})();
*/
