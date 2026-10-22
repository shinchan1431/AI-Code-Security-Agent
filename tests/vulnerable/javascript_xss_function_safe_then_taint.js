function updateProfile(profile, value) {
    profile.name = value;
}

const profile = { name: "safe" };

updateProfile(profile, "Alice");
document.body.innerHTML = profile.name;

updateProfile(profile, request.query.name);
document.body.innerHTML = profile.name;
