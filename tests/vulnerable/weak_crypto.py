import hashlib

data = "example-data"

md5_hash = hashlib.md5(data.encode()).hexdigest()

sha1_hash = hashlib.sha1(data.encode()).hexdigest()
