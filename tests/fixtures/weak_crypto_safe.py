import hashlib

data = b"example-data"

sha256_hash = hashlib.sha256(data).hexdigest()

sha3_hash = hashlib.sha3_256(data).hexdigest()


class HashWrapper:
    def md5(self, value):
        return value


wrapper = HashWrapper()
result = wrapper.md5(data)
