import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { ApiError } from "../utils/ApiError.js";
import { isValidObjectId } from "mongoose";
import { User } from "../models/user.model.js";
import FormData from "form-data";
import axios from "axios";

const generateImage = asyncHandler(async (req, res) => {
  try {
    console.log("Generate image request came.");
    const userId = req.user?._id;
    const { prompt } = req.body;

    if (!isValidObjectId(userId)) {
      console.log("Invalid user id");
      throw new ApiError(400, "Invalid user id");
    }
    const user = await User.findById(userId);
    if (!user) {
      console.log("User not found");
      throw new ApiError(404, "User not found");
    }
    if (prompt.trim() === "") {
      console.log("prompt Required");
      throw new ApiError(400, "Prompt is required");
    }

    if (user.creditBalance === 0 || user.creditBalance < 0) {
      console.log("No credits left");
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
          ...formData.getHeaders(),
        },
        responseType: "arraybuffer",
      },
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
    console.log("Image generated succesffully");
    return res
      .status(200)
      .json(new ApiResponse(200, responseData, "Image Generated Successfully"));
  } catch (error) {
    console.log("GENERATE ERROR:", error.response?.status);
    console.log("GENERATE ERROR DATA:", error.response?.data?.toString());
    console.log("GENERATE ERROR MSG:", error.message); // ← ADD THESE
    throw new ApiError(500, error?.message || "Something went wrong");
  }
});

export { generateImage };
