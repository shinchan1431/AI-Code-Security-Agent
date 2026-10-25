const profile = {
    details: {
        name: request.query.name
    }
};

element.innerHTML = profile.details.name;
