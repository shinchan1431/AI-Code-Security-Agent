// Vulnerable JavaScript fixture for security analyzer tests

const userInput = "console.log('hello')";

// Dangerous dynamic code execution
eval(userInput);