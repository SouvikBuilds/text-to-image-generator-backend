import { User } from "../models/user.model.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";
import { config } from "../config/config.js";
import { isValidObjectId } from "mongoose";
import razorpay from "razorpay";
import { Transaction } from "../models/transaction.model.js";

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
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
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
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
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
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
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
    const userId = req.user?._id;
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

const razorpayInstance = new razorpay({
  key_id: config.RAZORPAY_TEST_API_KEY,
  key_secret: config.RAZORPAY_TEST_KEY_SECRET,
});

const paymentrazorPay = asyncHandler(async (req, res) => {
  try {
    const { planId } = req.body;
    const userId = req.user?._id;
    const userData = await User.findById(userId);
    if (!isValidObjectId(userId)) {
      throw new ApiError(400, "Invalid user id");
    }
    if (!userId || !planId) {
      throw new ApiError(400, "Missing id details");
    }
    if (!userData) {
      throw new ApiError(404, "User not found");
    }
    let credits, plan, amount, date;
    switch (planId) {
      case "Basic":
        plan = "Basic";
        credits = 100;
        amount = 10;
        break;
      case "Advanced":
        plan = "Advanced";
        credits = 500;
        amount = 50;
        break;
      case "Business":
        plan = "Business";
        credits = 5000;
        amount = 250;
        break;
      default:
        throw new ApiError(404, "Plan not found");
    }
    date = Date.now();
    const transactionData = {
      userId,
      plan,
      amount,
      credits,
      date,
    };
    const newTransaction = await Transaction.create(transactionData);
    const options = {
      amount: amount * 100,
      currency: config.CURRENCY,
      receipt: newTransaction._id,
    };
    await razorpayInstance.orders.create(options, (error, order) => {
      if (error) {
        console.log(error);
        throw new ApiError(500, error?.message || "Something went wrong");
      }
      return res
        .status(200)
        .json(new ApiResponse(200, order, "Order created successfully"));
    });
  } catch (error) {
    console.log(error);
    throw new ApiError(500, error?.message || "Something went wrong");
  }
});

const verifyRazorPay = asyncHandler(async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
    
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      throw new ApiError(400, "Missing payment verification data");
    }

    const orderInfo = await razorpayInstance.orders.fetch(razorpay_order_id);

    if (orderInfo.status === "paid") {
      const transactionData = await Transaction.findById(orderInfo.receipt);
      
      if (!transactionData) {
        throw new ApiError(404, "Transaction not found");
      }

      if (transactionData.payment) {
        throw new ApiError(400, "Payment already processed");
      }

      const userData = await User.findById(transactionData.userId);
      if (!userData) {
        throw new ApiError(404, "User not found");
      }
      
      const creditBalance = userData.creditBalance + transactionData.credits;
      await User.findByIdAndUpdate(
        userData._id,
        {
          $set: {
            creditBalance: creditBalance,
          },
        },
        { new: true }
      );
      
      await Transaction.findByIdAndUpdate(
        transactionData._id,
        {
          $set: {
            payment: true,
          },
        },
        { new: true }
      );
      
      return res
        .status(200)
        .json(new ApiResponse(200, { success: true }, "Payment verified successfully"));
    } else {
      throw new ApiError(400, "Payment not completed");
    }
  } catch (error) {
    console.log(error);
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
  paymentrazorPay,
  verifyRazorPay,
};
