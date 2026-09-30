const user = {
    name: "Alice"
};

let profile = user;

profile = {
    name: "Bob"
};

element.innerHTML = profile.name;
