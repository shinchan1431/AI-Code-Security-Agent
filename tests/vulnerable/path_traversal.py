def read_file():
    filename = input("Enter filename: ")
    with open(filename, "r", encoding="utf-8") as file:
        return file.read()
