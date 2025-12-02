import dotenv from "dotenv";
dotenv.config("./.env");

export const config = {
  ORIGIN: process.env.ORIGIN,
  PORT: process.env.PORT || 8000,
  MONGODB_URL: process.env.MONGODB_URL,
  ACCESS_TOKEN_SECRET: process.env.ACCESS_TOKEN_SECRET,
  ACCESS_TOKEN_EXPIRY: process.env.ACCESS_TOKEN_EXPIRY,
  REFRESH_TOKEN_SECRET: process.env.REFRESH_TOKEN_SECRET,
  REFRESH_TOKEN_EXPIRY: process.env.REFRESH_TOKEN_EXPIRY,
  CLIPDROP_API_KEY: process.env.CLIPDROP_API_KEY,
  RAZORPAY_TEST_API_KEY: process.env.RAZORPAY_TEST_API_KEY,
  RAZORPAY_TEST_KEY_SECRET: process.env.RAZORPAY_TEST_KEY_SECRET,
  CURRENCY: process.env.CURRENCY,
};
