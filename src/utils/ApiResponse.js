// Class to handle API responses
class ApiResponse {
    // Constructor for the ApiResponse class
    constructor(
        statusCode, // HTTP status code
        data, // Data to be sent in the response
        message = "Success" // Message to be sent in the response
    ) {
        this.statusCode = statusCode // Setting the status code
        this.data = data // Setting the data
        this.message = message // Setting the message
        this.success = statusCode < 400 // Setting the success status
    }
}

// Exporting the ApiResponse class
export { ApiResponse }