import pickle

data = b"unsafe serialized data"

result = pickle.loads(data)

with open("data.pkl", "rb") as file:
    result = pickle.load(file)
