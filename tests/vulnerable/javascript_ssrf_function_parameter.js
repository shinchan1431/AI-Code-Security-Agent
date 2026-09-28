const target = request.query.url;

function fetchRemote(url) {
    return fetch(url);
}

fetchRemote(target);