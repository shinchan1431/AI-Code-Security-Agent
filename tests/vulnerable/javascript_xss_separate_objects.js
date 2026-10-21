const input = request.query.name;

const user = {
    name: input
};

const admin = {
    name: "Alice"
};

element.innerHTML = admin.name;
element.innerHTML = user.name;
