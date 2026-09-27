const userInput = request.query.key;

const obj = {};

obj[userInput] = "attacker-controlled";

obj["__proto__"] = {
    isAdmin: true
};

obj["constructor"]["prototype"] = {
    isAdmin: true
};