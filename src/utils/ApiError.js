// Class to handle API errors
class ApiError extends Error {
    // Constructor for the ApiError class
    constructor(
        statusCode, // HTTP status code
        message = "Something went wrong", // Error message
        errors = [], // Array of error messages
        stack = "" // Stack trace
    ) {
        super(message) // Call to the parent class constructor
        this.statusCode = statusCode // HTTP status code
        this.data = null // Data to be sent with the error
        this.message = message // Error message
        this.success = false; // Success status
        this.errors = errors // Array of error messages

        // If a stack trace is provided, use it
        if (stack) {
            this.stack = stack
        } else {
            // If no stack trace is provided, capture it
            Error.captureStackTrace(this, this.constructor)
        }

    }
}

// Export the ApiError class
export { ApiError }