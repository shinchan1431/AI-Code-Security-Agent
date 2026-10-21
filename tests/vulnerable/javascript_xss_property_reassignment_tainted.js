const input = request.query.name;

const user = {
    name: "Alice"
};

user.name = input;

element.innerHTML = user.name;
