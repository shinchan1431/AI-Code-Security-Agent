const input = window.location.search;
const values = ["safe", input];

const [first, second] = values;

document.getElementById("output").innerHTML = second;
