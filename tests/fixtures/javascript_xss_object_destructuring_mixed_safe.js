const userInput = request.query.name;
const user = {
    name: userInput,
    email: "safe@example.com"
};
const { name, email } = user;
element.innerHTML = email;
