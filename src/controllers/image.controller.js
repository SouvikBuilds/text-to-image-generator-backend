import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { ApiError } from "../utils/ApiError.js";
import { isValidObjectId } from "mongoose";
import { User } from "../models/user.model.js";
import FormData from "form-data";
import axios from "axios";

const generateImage = asyncHandler(async (req, res) => {
  try {
    const userId = req.user?._id;
    const { prompt } = req.body;

    if (!isValidObjectId(userId)) {
      throw new ApiError(400, "Invalid user id");
    }
    const user = await User.findById(userId);
    if (!user) {
      throw new ApiError(404, "User not found");
    }
    if (prompt.trim() === "") {
      throw new ApiError(400, "Prompt is required");
    }

    if (user.creditBalance === 0 || user.creditBalance < 0) {
      throw new ApiError(400, "You have no credits left");
    }

    const formData = new FormData();
    formData.append("prompt", prompt);

    const { data } = await axios.post(
      "https://clipdrop-api.co/text-to-image/v1",
      formData,
      {
        headers: {
          "x-api-key": process.env.CLIPDROP_API_KEY,
          "Content-Type": "multipart/form-data",
        },
        responseType: "arraybuffer",
      }
    );

    const base64Image = Buffer.from(data).toString("base64");
    const resultImage = `data:image/png;base64,${base64Image}`;
    await User.findByIdAndUpdate(user?._id, {
      creditBalance: user.creditBalance - 1,
    });

    const responseData = {
      image: resultImage,
      creditBalance: user.creditBalance - 1,
    };
    return res
      .status(200)
      .json(new ApiResponse(200, responseData, "Image Generated Successfully"));
  } catch (error) {
    console.error(
      "Image generation error:",
      error.response?.data || error.message
    );
    throw new ApiError(500, error?.message || "Something went wrong");
  }
});

export { generateImage };
