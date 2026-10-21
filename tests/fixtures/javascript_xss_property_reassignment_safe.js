const input = request.query.name;

const user = {
    name: input
};

user.name = "Alice";

element.innerHTML = user.name;
