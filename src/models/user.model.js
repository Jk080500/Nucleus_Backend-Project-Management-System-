import mongoose, { Schema } from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";

const UserSchema = new Schema(
  {
    avatar: {
      type: {
        url: String,
        localPath: String,
      },
      default: {
        url: `https://placehold.co/200x200`,
        localPath: "",
      },
    },

    username: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },

    fullName: {
      type: String,
      trim: true,
    },

    password: {
      type: String,
      required: [true, "Password is Required"],
    },

    isEmailVerified: {
      type: Boolean,
      default: false,
    },

    refreshToken: {
      type: String,
    },

    forgotPasswordToken: {
      type: String,
    },

    forgotPasswordExpiry: {
      type: Date,
    },

    emailVerificationToken: {
      type: String,
    },

    emailVerificationExpiry: {
      type: String,
    },
  },
  {
    timestamps: true,
  },
);

/* This code snippet is a pre-save hook in Mongoose that is executed before saving a user document to
the database. */
UserSchema.pre("save", async function (next) {
  /* The line `if (!this.isModified("password")) return next();` is a conditional check in a pre-save
    hook in Mongoose. It checks if the "password" field of the user document has been modified before
    saving the document to the database. */
  if (!this.isModified("password")) return next();

  /* `this.password = await bcrypt.hash(this.password, 10);` is a line of code within a pre-save hook
  in Mongoose that is responsible for hashing the user's password before saving it to the database. */
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

/* This code snippet is defining a method called `isPasswordCorrect` on the `UserSchema` in Mongoose.
This method is used to compare a plain text password input with the hashed password stored in the
user document. */
UserSchema.methods.isPasswordCorrect = async function (password) {
  return await bcrypt.compare(password, this.password);
};

//  Generate Access Token and Refresh Token

/* The `UserSchema.methods.generateAccessToken` function defined in the Mongoose schema is responsible
for generating an access token for a user. Here's a breakdown of what the function does: */
UserSchema.methods.generateAccessToken = function () {
  const payload = {
    _id: this._id,
    email: this.email,
    username: this.username,
  };
  return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
  });
};

/* The `UserSchema.methods.generateRefreshToken` function defined in the Mongoose schema is responsible
for generating a refresh token for a user. Here's a breakdown of what the function does: */
UserSchema.methods.generateRefreshToken = function () {
  const payload = {
    _id: this._id,
    email: this.email,
    username: this.username,
  };

  return jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
  });
};

/* The `UserSchema.method.generateTemproraryToken` function defined in the Mongoose schema is
responsible for generating a temporary token for a user. */
UserSchema.methods.generateTemproraryToken = function () {
  const unHashedToken = crypto.randomBytes(20).toString("hex");
  const hashedToken = crypto
    .createHash("sha256")
    .update(unHashedToken)
    .digest("hex");

  const tokenExpiry = Date.now() + 20 * 60 * 1000; //20 minutes
  return { unHashedToken, hashedToken, tokenExpiry };
};

export const User = mongoose.model("User", UserSchema);
