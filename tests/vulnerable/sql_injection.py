import sqlite3


def find_user(username):
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    query = "SELECT * FROM users WHERE username = '" + username + "'"

    cursor.execute(query)

    return cursor.fetchall()