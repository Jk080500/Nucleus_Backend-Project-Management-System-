/**
 * The asyncHandler function is a higher-order function that wraps around an asynchronous request
 * handler and ensures any errors are caught and passed to the next middleware.
 * @param requestHandler - The `requestHandler` parameter is a function that handles incoming HTTP
 * requests. It takes three parameters: `req` (the request object), `res` (the response object), and
 * `next` (the next middleware function in the stack).
 * @returns The `asyncHandler` function is being returned.
 */

const asyncHandler = (requestHandler) => {
  return (req, res, next) => {
    Promise.resolve(requestHandler(req, res, next)).catch((err) => next(err));
  };
};

export { asyncHandler };
