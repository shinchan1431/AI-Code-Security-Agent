// Vulnerable Node.js command execution fixture

const child_process = require("child_process");

const userInput = "whoami";

child_process.exec(userInput);