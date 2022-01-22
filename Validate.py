import json
import random

with open('data.json') as json_file:
    data = json.load(json_file)
    seed = data['seed'][0]
    nce_list = data['nce_list'][0]
    print
    
    
    for l in range (len(nce_list)):
        random.seed(seed+nce_list[l])
        print(random.randint(1,49))
