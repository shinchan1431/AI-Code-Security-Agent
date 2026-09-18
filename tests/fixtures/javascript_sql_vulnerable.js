// JavaScript SQL injection fixture

const userId = "123";

db.execute(
    "SELECT * FROM users WHERE id = " + userId
);