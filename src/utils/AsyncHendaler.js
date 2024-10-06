// Function to handle asynchronous requests
const asyncHandler = (requestHandler) => {
    return (req, res, next) => {
        // Resolving the request handler and catching any errors
        Promise.resolve(requestHandler(req, res, next)).catch((err) => next(err))
    }
}

// Exporting the asyncHandler function
export { asyncHandler }

