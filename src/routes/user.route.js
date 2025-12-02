import {
  registerUser,
  generateAccessAndRefreshToken,
  refreshAccessToken,
  loginUser,
  logOutUser,
  getCurrentUser,
  changeCurrentPassword,
  userCredit,
} from "../controllers/user.controller.js";
import express, { Router } from "express";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router();
router.route("/register").post(registerUser);
router.route("/login").post(loginUser);
router.route("/logout").post(verifyJWT, logOutUser);
router.route("/refresh-token").post(refreshAccessToken);
router.route("/").get(verifyJWT, getCurrentUser);
router.route("/change-password").patch(verifyJWT, changeCurrentPassword);
router.route("/credit").get(verifyJWT, userCredit);

export default router;
