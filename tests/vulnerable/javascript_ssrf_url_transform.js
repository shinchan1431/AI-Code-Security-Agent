const target = request.query.url;

const url = new URL(target);

fetch(url);
