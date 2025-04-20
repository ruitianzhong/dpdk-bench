import json
import os


def write_json(filename, obj):
    json_str = json.dumps(obj)
    with open(filename, 'w') as f:
        f.write(json_str)


FIG_PATH = "./result/fig/"
JSON_PATH = "./result/json/"
