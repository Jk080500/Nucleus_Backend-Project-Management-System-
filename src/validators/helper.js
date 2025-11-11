import { body } from "express-validator";

const userRegisterValidator = () => {
  retrun[
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
    body("fullName").trim().notEmpty().withMessage("FullName is mandatory"))
  ];
};

export { userRegisterValidator };
