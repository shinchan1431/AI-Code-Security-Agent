const input = request.query.name;

const source = {
    name: input
};

const alias = source;

alias.name = "safe text";

element.innerHTML = source.name;
element.innerHTML = alias.name;
