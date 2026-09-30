const input = request.query.name;

const user = {
    name: input
};

let profile = user;

profile = {
    name: "Alice"
};

element.innerHTML = profile.name;
