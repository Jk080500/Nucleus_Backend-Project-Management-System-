import { User } from "../models/user.model.js";
import { ApiResponse } from "../utils/api-response.js";
import { ApiError } from "../utils/api-errors.js";
import { asyncHandler } from "../utils/async-handler.js";
import { emailVerificationContent, sendEmail } from "../utils/mail.js";

const generateAccessAndRefreshToken = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });
    return { accessToken, refreshToken };
  } catch (error) {
    console.log("Error in generateAccessAndRefreshToken");
    throw new ApiError(
      500,
      "Something went wrong while generating Access Token",
    );
  }
};

const registerUser = asyncHandler(async (req, res) => {
  const { email, username, fullName, password, role } = req.body;

  const existingUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (existingUser) {
    throw new ApiError(409, "User with Email or Username already exists", []);
  }

  const user = await User.create({
    email,
    password,
    username,
    fullName,
    isEmailVerified: false,
  });

  const { unHashedToken, hashedToken, tokenExpiry } =
    user.generateTemproraryToken();
  user.emailVerificationToken = hashedToken;
  user.emailVerificationExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });

  await sendEmail({
    email: user?.email,
    subject: "Please verify you email",
    mailgenContent: emailVerificationContent(
      user.username,
      `${req.protocol}://${req.get("host")}/api/v1/auth/verify-email/${unHashedToken}`,
    ),
  });

  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken -emailVerificationToken -emailVerificationExpiry",
  );

  if (!createdUser) {
    console.log("Error in RegisterUser Controller");
    throw new ApiError(500, "Something Went Wrong While registering User");
  }

  return res
    .status(201)
    .json(
      new ApiResponse(
        200,
        { user: createdUser },
        `User Registration Successfully and verification email has been sent on your email: ${email}`,
      ),
    );
});

export { registerUser };
