const target = request.query.url;

const url = "https://proxy.example.com/?target=" + target;

fetch(url);