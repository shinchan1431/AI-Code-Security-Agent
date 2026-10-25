const profile = {
    details: {
        /*
           this multiline comment contains a brace: }
        */
        name: request.query.name
    }
};

element.innerHTML = profile.details.name;
