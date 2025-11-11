import mailgen from "mailgen";
import nodemailer from "nodemailer";

/**
 * The `sendEmail` function generates an email using Mailgen, sets up a nodemailer transport, and sends
 * the email using the configured transporter.
 * @param options - The `sendEmail` function you provided is an asynchronous function that uses
 * `Mailgen` to generate both plaintext and HTML email content, and `nodemailer` to send the email
 * using the `MAILTRAP` SMTP configuration.
 */
const sendEmail = async (options) => {
  const mailGenerator = new mailgen({
    theme: "default",
    product: {
      name: "Nucleus Task Manager",
      link: "https://nucleus.co",
    },
  });

  const emailTextual = mailGenerator.generatePlaintext(options.mailgenContent);
  const emailHtml = mailGenerator.generate(options.mailgenContent);

  const transporter = nodemailer.createTransport({
    host: process.env.MAILTRAP_SMTP_HOST,
    port: process.env.MAILTRAP_SMTP_PORT,
    auth: {
      user: process.env.MAILTRAP_SMTP_USER,
      pass: process.env.MAILTRAP_SMTP_PASS,
    },
  });

  const mail = {
    from: "mail.nucleus.com",
    to: options.email,
    subject: options.subject,
    text: emailTextual,
    html: emailHtml,
  };

  try {
    await transporter.sendMail(mail);
  } catch (error) {
    console.error(
      `Email server failed! Make sure MAILTRAP connection is up and running`,
    );
    console.error("Error: ", error);
  }
};

/**
 * The function `emailVerificationContent` generates an email verification content with a personalized
 * message and a button to verify the email.
 * @param username - The `username` parameter in the `emailVerificationContent` function represents the
 * name of the user for whom the email verification content is being generated.
 * @param verficationUrl - The `verficationUrl` parameter in the `emailVerificationContent` function is
 * a URL that the user will click on to verify their email address. This URL will typically lead to a
 * verification page or process to confirm the user's email ownership.
 * @returns An object containing the email verification content with the provided username and
 * verification URL. The object has properties for the name, intro message, action instructions with a
 * button to verify the email, and an outro message for assistance or questions.
 */
const emailVerificationContent = (username, verficationUrl) => {
  return {
    body: {
      name: username,
      intro:
        "Welcome to Nucleus! We’re excited to have you here and can’t wait for you to explore what’s possible.",
      action: {
        intructions: "To verify you email please click on the following button",
        button: {
          color: "#0c70cdff",
          text: "Verify your email",
          link: verficationUrl,
        },
      },
      outro:
        "Need help, or have questions? Just reply to this email, we'd love to help.",
    },
  };
};

/**
 * The function `forgotPasswordContent` generates an email content object for a password reset request,
 * including the username, reset instructions, and a button to reset the password.
 * @param username - The `username` parameter in the `forgotPasswordContent` function represents the
 * name of the user for whom the password reset email is being sent.
 * @param passwordResetUrl - The `passwordResetUrl` parameter in the `forgotPasswordContent` function
 * is the URL where the user can reset their password. This URL is included in the email content to
 * direct the user to the password reset page.
 * @returns The function `forgotPasswordContent` returns an object with a `body` property containing
 * information for a password reset email. The object includes the `name` of the user, an `intro`
 * message explaining the reason for the email, an `action` object with instructions and a button to
 * reset the password, and an `outro` message indicating no action is needed if the user did not
 * request
 */
const forgotPasswordContent = (username, passwordResetUrl) => {
  return {
    body: {
      name: username,
      intro:
        "You have received this email because a password reset request for your account was received.",
      action: {
        intructions: "Click the button below to reset your password:",
        button: {
          color: "#DC4D2F",
          text: "Reset your password",
          link: passwordResetUrl,
        },
      },
      outro:
        "If you did not request a password reset, no further action is required on your part.",
    },
  };
};

export { emailVerificationContent, forgotPasswordContent, sendEmail };
