const profile = {
    details: {
        name: request.query.name
    }
};

profile.details.name = "safe text";
element.innerHTML = profile.details.name;
