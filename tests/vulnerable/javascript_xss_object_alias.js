const input = request.query.name;

const user = {
    name: input
};

const profile = user;

element.innerHTML = profile.name;
