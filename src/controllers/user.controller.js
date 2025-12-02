import { User } from "../models/user.model.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";
import { config } from "../config/config.js";
import { isValidObjectId } from "mongoose";

const registerUser = asyncHandler(async (req, res) => {
  try {
    const { name, email, password } = req.body;
    [name, email, password].some((field) => {
      if (field.trim() === "" || field.trim().length === 0) {
        throw new ApiError(400, `${field} is required`);
      }
    });
    const existedUser = await User.findOne({ email });
    if (existedUser) {
      throw new ApiError(409, "User already exists");
    }
    const newUser = await User.create({
      name,
      email,
      password,
    });
    const createdUser = await User.findById(newUser?._id).select(
      "-password -refreshToken"
    );
    return res
      .status(200)
      .json(new ApiResponse(200, createdUser, "User created successfully"));
  } catch (error) {
    throw new ApiError(500, error?.message || "Something went wrong");
  }
});

const generateAccessAndRefreshToken = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();
    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });
    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      500,
      error?.message || "Something went wrong while generating tokens"
    );
  }
};

const refreshAccessToken = asyncHandler(async (req, res) => {
  try {
    const incomingRefreshToken =
      req.cookies.refreshToken || req.body.refreshToken;
    if (!incomingRefreshToken) {
      throw new ApiError(401, "Unauthorized request");
    }
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      config.REFRESH_TOKEN_SECRET
    );
    const user = await User.findById(decodedToken?._id);
    if (!user) {
      throw new ApiError(401, "Invalid refresh token");
    }
    if (incomingRefreshToken !== user?.refreshToken) {
      throw new ApiError(401, "Refresh token is expired or used");
    }
    const options = {
      httpOnly: true,
      secure: true,
    };
    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(
      user?._id
    );
    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", refreshToken, options)
      .json(
        new ApiResponse(
          200,
          { accessToken, refreshToken },
          "Access token refreshed"
        )
      );
  } catch (error) {
    throw new ApiError(
      500,
      error?.message || "Somethign went wrong while refreshing Access Token"
    );
  }
});

const loginUser = asyncHandler(async (req, res) => {
  try {
    const { email, password } = req.body;
    [email, password].some((field) => {
      if (field.trim() === "" || field.trim().length === 0) {
        throw new ApiError(400, `${field} is required`);
      }
    });
    const user = await User.findOne({ email });
    if (!user) {
      throw new ApiError(404, "User does not exist");
    }
    const isPasswordCorrect = await user.isPasswordCorrect(password);
    if (!isPasswordCorrect) {
      throw new ApiError(401, "Invalid user credentials");
    }
    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(
      user?._id
    );
    const options = {
      httpOnly: true,
      secure: true,
    };
    const loggedInUser = await User.findById(user?._id).select(
      "-password -refreshToken"
    );
    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", refreshToken, options)
      .json(
        new ApiResponse(
          200,
          {
            user: loggedInUser,
            accessToken,
            refreshToken,
          },
          "User logged in successfully"
        )
      );
  } catch (error) {
    throw new ApiError(500, error?.message || "Something went wrong");
  }
});

const logOutUser = asyncHandler(async (req, res) => {
  try {
    const user = await User.findById(req.user?._id);
    if (!user) {
      throw new ApiError(404, "User not found");
    }

    await User.findByIdAndUpdate(
      req.user?._id,
      {
        $unset: {
          refreshToken: 1,
        },
      },
      { new: true }
    );
    const options = {
      httpOnly: true,
      secure: process.env.NODE_ENV == "production",
    };
    return res
      .status(200)
      .clearCookie("accessToken", options)
      .clearCookie("refreshToken", options)
      .json(new ApiResponse(200, {}, "User logged out successfully"));
  } catch (error) {
    throw new ApiError(500, error?.message || "Something went wrong");
  }
});

const getCurrentUser = asyncHandler(async (req, res) => {
  try {
    const user = await User.findById(req.user?._id).select(
      "-password -refreshToken"
    );
    if (!user) {
      throw new ApiError(404, "User not found");
    }
    return res
      .status(200)
      .json(new ApiResponse(200, user, "User fetched successfully"));
  } catch (error) {
    throw new ApiError(500, error?.message || "Something went wrong");
  }
});

const changeCurrentPassword = asyncHandler(async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    [oldPassword, newPassword].some((field) => {
      if (field.trim() === "" || field.trim().length === 0) {
        throw new ApiError(400, `${field} is required`);
      }
    });
    const user = await User.findById(req.user?._id);
    if (!user) {
      throw new ApiError(404, "User not found");
    }
    if (user?._id.toString() !== req.user?._id.toString()) {
      throw new ApiError(403, "You are not authorized to change password");
    }
    const matchPassword = await user.isPasswordCorrect(oldPassword);
    if (!matchPassword) {
      throw new ApiError(401, "Invalid old password");
    }
    user.password = newPassword;
    await user.save();
    return res
      .status(200)
      .json(new ApiResponse(200, {}, "Password changed successfully"));
  } catch (error) {
    throw new ApiError(
      500,
      error?.message || "Something went wrong while changing password"
    );
  }
});

const userCredit = asyncHandler(async (req, res) => {
  try {
    const { userId } = req.query;
    if (!isValidObjectId(userId)) {
      throw new ApiError(400, "Invalid user id");
    }
    const user = await User.findById(userId);
    if (!user) {
      throw new ApiError(404, "User not found");
    }
    const userData = {
      name: user.name,
      credit: user.creditBalance,
    };

    return res
      .status(200)
      .json(
        new ApiResponse(200, userData, "Credit balance fetched successfully")
      );
  } catch (error) {
    throw new ApiError(500, error?.message || "Something went wrong");
  }
});

export {
  registerUser,
  generateAccessAndRefreshToken,
  refreshAccessToken,
  loginUser,
  logOutUser,
  getCurrentUser,
  changeCurrentPassword,
  userCredit,
};
