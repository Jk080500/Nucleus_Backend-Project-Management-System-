/* The `ApiResponse` class is a JavaScript class that represents a response object with status code,
data, message, and success indicator. */

class ApiResponse {
  constructor(statusCode, data, message = "Success") {
    this.statusCode = statusCode;
    this.data = data;
    this.message = message;
    this.success = statusCode < 400;
  }
}

export { ApiResponse };
