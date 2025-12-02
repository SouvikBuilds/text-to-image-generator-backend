import dotenv from "dotenv";
dotenv.config("");

import { config } from "../config/config.js";
import { DB_NAME } from "../constant.js";
import mongoose from "mongoose";

export const connectDB = async () => {
  try {
    const MONGODB_URL = config.MONGODB_URL;
    const connectionInstance = await mongoose.connect(
      `${MONGODB_URL}/${DB_NAME}`
    );
    console.log(
      `MongoDB connected !! DB HOST: ${connectionInstance.connection.host}`
    );
  } catch (error) {
    console.log("Some Error Occured while connecting MONGO DB", error);
    process.exit(1);
  }
};
