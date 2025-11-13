import { body } from "express-validator";

const userRegisterValidator = () => {
  return [
    ((body("email")
      .trim()
      .notEmpty()
      .withMessage("Email is mandatory")
      .isEmail()
      .withMessage("Email is invalid"),
    body("username")
      .trim()
      .notEmpty()
      .withMessage("Username is mandatory")
      .isLowercase()
      .withMessage("Username must be in lower case")
      .isLength({ min: 3 })
      .withMessage("Username must be atleast 3 characters long")),
    body("password").trim().notEmpty().withMessage("Password is mandatory"),
    body("fullName").trim().notEmpty().withMessage("FullName is mandatory")),
  ];
};

const userLoginValidator = () => {
  return [
    body("email").optional().isEmail().withMessage("Email is Invalid"),
    body("password").notEmpty().withMessage("Password is Mandatory"),
  ];
};

const userChangeCurrentPasswordValidator = () => {
  return [
    (body("oldPassword").notEmpty().withMessage("Old Password is Required"),
    body("newPassword").notEmpty().withMessage(" New Password is Required")),
  ];
};

const userForgotPasswordValidator = () => {
  return [
    body("email")
      .notEmpty()
      .withMessage("Email is Required")
      .isEmail()
      .withMessage("Please Enter Valid Email"),
  ];
};

const userResetForgotPasswordValidator = () => {
  return [body("newPassword").notEmpty().withMessage("Password is required")];
};

export {
  userRegisterValidator,
  userLoginValidator,
  userChangeCurrentPasswordValidator,
  userForgotPasswordValidator,
  userResetForgotPasswordValidator,
};
