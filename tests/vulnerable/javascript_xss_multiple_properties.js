const input = request.query.name;

const user = {
    name: input,
    role: "admin"
};

element.innerHTML = user.name;
element.innerHTML = user.role;
