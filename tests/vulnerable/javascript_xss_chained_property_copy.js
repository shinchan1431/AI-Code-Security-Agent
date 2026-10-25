const input = request.query.name;

const first = {
    name: input
};

const second = {
    name: "safe text"
};

const third = {
    name: "safe text"
};

second.name = first.name;
third.name = second.name;

element.innerHTML = third.name;
