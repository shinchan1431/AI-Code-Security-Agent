const input = request.query.name;

const source = {
    name: "safe text"
};

const alias = source;

alias.name = "still safe";
source.name = input;

element.innerHTML = alias.name;
