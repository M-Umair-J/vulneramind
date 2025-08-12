import msgpack
import requests

url = "https://127.0.0.1:55552/api/"
auth_data = ['auth.login', 'msf', 'abc123']  # <-- fixed here
headers = {'Content-Type': 'binary/message-pack'}

resp = requests.post(url, data=msgpack.packb(auth_data), headers=headers, verify=False)

unpacker = msgpack.Unpacker()
unpacker.feed(resp.content)
for obj in unpacker:
    print(obj)
