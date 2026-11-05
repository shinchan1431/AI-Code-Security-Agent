const input = window.location.search;
const values = ["safe", input];

const alias = values;
const [first, second] = alias;

document.getElementById("output").innerHTML = second;
