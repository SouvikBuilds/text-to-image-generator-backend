import mongoose, { Schema, model } from "mongoose";
import { User } from "./user.model.js";
const transactionSchema = new Schema(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: User,
      required: true,
    },
    plan: {
      type: String,
      required: true,
    },
    amount: {
      type: Number,
      required: true,
    },
    credits: {
      type: Number,
      required: true,
    },
    payment: {
      type: Boolean,
      default: false,
    },
    date: {
      type: Number,
    },
  },
  { timestamps: true }
);
export const Transaction = model("Transaction", transactionSchema);
